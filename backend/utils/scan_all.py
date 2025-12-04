from pathlib import Path
import subprocess
import json
import sys
import logging
import argparse
import concurrent.futures
import time
import requests
from urllib.parse import urlparse

# --- TRICK: REDIRECT STDOUT TO STDERR GLOBALLY ---
original_stdout = sys.stdout
sys.stdout = sys.stderr

# Setup Logger
log_file = Path(__file__).resolve().parent / 'scan_all.log'
logger = logging.getLogger("scan_all")
logger.setLevel(logging.DEBUG)
if logger.hasHandlers():
    logger.handlers.clear()
file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
file_handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
stream_handler = logging.StreamHandler(sys.stderr)
stream_handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# Import Modules
try:
    from ZAPScanner import execute_zap_scan, shutdown_zap
    from techDetector import detect_software, search_cves_list
    from xss_sqli_tester import detect_form, test_injection, xss_payloads, sqli_payloads
    from nmapScanner import run_nmap 
    from CustomActiveScanner import run_custom_scan 
    from SSLScanner import run_ssl_scan
    from rateLimit import run_rate_limit_test
except ImportError as e:
    logger.error(f"Import Error: {e}")
    sys.stdout = original_stdout
    print(json.dumps({"error": f"Import Error: {e}"}))
    sys.exit(1)

# --- FUNGSI NORMALISASI URL ---
def normalize_targets(raw_input):
    if not raw_input.startswith(('http://', 'https://')):
        if ':443' in raw_input:
             zap_target = 'https://' + raw_input
        else:
             zap_target = 'http://' + raw_input
    else:
        zap_target = raw_input

    parsed = urlparse(zap_target)
    nmap_target = parsed.hostname 
    if not nmap_target:
        nmap_target = raw_input.split(':')[0]

    return zap_target, nmap_target

# --- WRAPPERS ---
def run_nmap_scan(nmap_host, nmap_params):
    logger.info(f"[NMAP] Target: {nmap_host}")
    try:
        params = nmap_params.copy()
        if 'specific_ports_str' in params:
            port_str = params.pop('specific_ports_str')
            if params.get('ports_option') == 'specific' and port_str:
                try:
                    params['specific_ports'] = [int(p.strip()) for p in port_str.split(',') if p.strip().isdigit()]
                except:
                    logger.warning("Format port spesifik salah, fallback ke top1000")
                    params['ports_option'] = 'top1000'
            else:
                params['specific_ports'] = None

        if 'timeout' in params: del params['timeout']
        timeout_val = 360 
        
        result = run_nmap(target=nmap_host, timeout=timeout_val, **params)
        return {'nmap_result': result}
    except Exception as e:
        logger.error(f"Nmap Critical Error: {e}")
        return {'nmap_result': {"raw_stderr": f"Internal Error: {str(e)}", "open_ports": []}}

def run_tech_detector(target_url):
    logger.info(f"[TECH] Detecting: {target_url}")
    try:
        techs = detect_software(target_url)
        return {'tech': techs}
    except Exception as e:
        logger.error(f"Tech Error: {e}")
        return {'tech': []}

def run_xss_sqli(target_url):
    logger.info(f"[INJECTION] Testing: {target_url}")
    try:
        xss_results = []
        sqli_results = []
        forms = detect_form(target_url)
        if not forms: logger.info("[INJECTION] Tidak ada form ditemukan.")
        
        for form in forms:
            method = form.get('method', 'get')
            action = form.get('action', target_url)
            inputs = form.get('inputs', [])
            xss_results.extend(test_injection(target_url, method, action, inputs, xss_payloads, type='xss'))
            sqli_results.extend(test_injection(target_url, method, action, inputs, sqli_payloads, type='sqli'))
        return {'xss_results': xss_results, 'sqli_results': sqli_results}
    except Exception as e:
        logger.error(f"Injection Error: {e}")
        return {'xss_results': [], 'sqli_results': []}

def run_zap(target_url):
    logger.info("[ZAP] Running Hybrid Scan...")
    all_alerts = []
    try:
        zap_data = execute_zap_scan(target_url, max_depth=2, selenium_only=False, traditional_only=False)
        if zap_data and 'categories' in zap_data:
            for cat in zap_data['categories'].values():
                all_alerts.extend(cat.get('alerts', []))
        logger.info("[ZAP] Running Custom Active Scan...")
        custom_alerts = run_custom_scan(target_url)
        all_alerts.extend(custom_alerts)
    except Exception as e:
        logger.error(f"ZAP/Custom Error: {e}")
    return {'zap_alerts': all_alerts}

# --- SCORING FUNCTIONS ---
def cvss_to_score(cvss_list):
    if not cvss_list: return 100
    try:
        max_cvss = max(cvss_list)
        return max(0, 100 - (max_cvss * 10))
    except: return 100

def zap_to_score(alerts, ssl_data=None):
    score = 100
    has_high = False
    has_medium = False
    
    if alerts:
        for a in alerts:
            risk = str(a.get('risk', '')).lower()
            if 'high' in risk or 'critical' in risk: has_high = True
            if 'medium' in risk: has_medium = True
            
    if ssl_data and isinstance(ssl_data, dict):
        issues = (ssl_data.get('weak_ciphers') or []) + (ssl_data.get('vulnerabilities') or [])
        for i in issues:
            if "Critical" in i or "High" in i or "ROBOT" in i or "Heartbleed" in i: has_high = True
            elif "Medium" in i: has_medium = True

    if has_high: return 40 
    if has_medium: return 65 
    return 90

# --- NEW: NMAP SCORING ---
def nmap_to_score(nmap_data):
    """
    Menurunkan skor jika ada port berisiko tinggi (Critical/High) yang terbuka.
    """
    if not nmap_data or not nmap_data.get('open_ports'):
        return 100 # Aman atau tidak dijalankan
        
    lowest_score = 100
    
    for p in nmap_data['open_ports']:
        risk = p.get('risk', 'Info')
        
        if risk == 'Critical': 
            # Port Database/Telnet/FTP terbuka -> Langsung D
            return 40 
        if risk == 'High':
            # High Risk Port -> C
            lowest_score = min(lowest_score, 60)
        if risk == 'Medium':
            # Medium Risk (HTTP 80) -> B
            lowest_score = min(lowest_score, 75)
            
    return lowest_score

def score_to_grade(score):
    if score is None: return "N/A"
    try: s = float(score)
    except: return "N/A"
    if s >= 90: return "A"
    if s >= 75: return "B"
    if s >= 60: return "C"
    if s >= 40: return "D"
    return "F"

def analyze_impact_sentiment(results):
    """
    Analisis dampak berdasarkan hasil AKTUAL, bukan asumsi.
    Jika test tidak dijalankan (None), jangan hitung ke scoring.
    """
    # Cek apa saja yang benar-benar DIJALANKAN (bukan None)
    tests_run = {
        'tech': results.get('tech') is not None,
        'cves': results.get('cves') is not None,
        'xss': results.get('xss_results') is not None,
        'sqli': results.get('sqli_results') is not None,
        'zap': results.get('zap_alerts') is not None,
        'ssl': results.get('ssl_result') is not None,
        'nmap': results.get('nmap_result') is not None,
        'ratelimit': results.get('ratelimit_result') is not None,
    }
    
    # Jika SEMUA test None -> tidak ada yang dijalankan
    if not any(tests_run.values()):
        return "TIDAK ADA TEST DIJALANKAN"
    
    score = 0
    findings = []
    
    # 1. INJECTION (XSS + SQLi)
    xss_count = len(results.get('xss_results') or []) if results.get('xss_results') is not None else 0
    sqli_count = len(results.get('sqli_results') or []) if results.get('sqli_results') is not None else 0
    if xss_count > 0:
        score += 50
        findings.append(f"XSS: {xss_count} vulnérabilité(s)")
    if sqli_count > 0:
        score += 50
        findings.append(f"SQLi: {sqli_count} vulnérabilité(s)")
    
    # 2. CVE (Software Vulnerability)
    cves = results.get('cves') or []
    if cves is not None and len(cves) > 0:
        critical_cves = [c for c in cves if c.get('cvss_score', 0) >= 9]
        high_cves = [c for c in cves if 7 <= c.get('cvss_score', 0) < 9]
        medium_cves = [c for c in cves if 4 <= c.get('cvss_score', 0) < 7]
        
        if critical_cves:
            score += 30
            findings.append(f"CVE Critical: {len(critical_cves)}")
        if high_cves:
            score += 15
            findings.append(f"CVE High: {len(high_cves)}")
        if medium_cves:
            score += 5
            findings.append(f"CVE Medium: {len(medium_cves)}")
    
    # 3. ZAP (Configuration & Headers)
    zap_alerts = results.get('zap_alerts') or []
    if zap_alerts is not None and len(zap_alerts) > 0:
        high_alerts = [a for a in zap_alerts if 'high' in str(a.get('risk', '')).lower()]
        medium_alerts = [a for a in zap_alerts if 'medium' in str(a.get('risk', '')).lower()]
        
        if high_alerts:
            score += 15
            findings.append(f"ZAP High: {len(high_alerts)}")
        if medium_alerts:
            score += 5
            findings.append(f"ZAP Medium: {len(medium_alerts)}")
    
    # 4. SSL/TLS
    ssl_result = results.get('ssl_result')
    if ssl_result is not None and isinstance(ssl_result, dict):
        ssl_issues = (ssl_result.get('weak_ciphers') or []) + (ssl_result.get('vulnerabilities') or [])
        if ssl_issues:
            score += 10
            findings.append(f"SSL Issues: {len(ssl_issues)}")
    
    # 5. NMAP (Port Risk)
    nmap_result = results.get('nmap_result')
    if nmap_result is not None and isinstance(nmap_result, dict):
        open_ports = nmap_result.get('open_ports') or []
        critical_ports = [p for p in open_ports if p.get('risk') == 'Critical']
        high_ports = [p for p in open_ports if p.get('risk') == 'High']
        
        if critical_ports:
            score += 25
            findings.append(f"Nmap Critical Ports: {len(critical_ports)}")
        if high_ports:
            score += 10
            findings.append(f"Nmap High Ports: {len(high_ports)}")
    
    # 6. RATE LIMIT
    rl_result = results.get('ratelimit_result')
    if rl_result is not None and isinstance(rl_result, dict):
        rl_summary = rl_result.get('summary', '').upper()
        if 'RENTAN' in rl_summary or 'VULNERABLE' in rl_summary:
            score += 15
            findings.append("Rate Limit: VULNERABLE")
    
    # Sentiment Analysis berdasarkan score AKTUAL
    findings_str = ", ".join(findings) if findings else "Tidak ada vulnerability ditemukan"
    
    if score >= 75:
        return f"🔴 KRITIS: {findings_str}"
    elif score >= 50:
        return f"🟠 BERISIKO TINGGI: {findings_str}"
    elif score >= 25:
        return f"🟡 PERINGATAN: {findings_str}"
    elif score >= 1:
        return f"🔵 INFO: {findings_str}"
    else:
        return f"🟢 AMAN: Tidak ada isu signifikan ditemukan"

# --- MAIN ORCHESTRATOR ---
def main_scan(raw_url_input, args, ratelimit_level=0):
    start_time = time.time()  # Catat waktu mulai
    results = {
        'tech': None, 'cves': None, 'zap_alerts': None, 'xss_results': None, 
         'sqli_results': None, 'nmap_result': None, 'ssl_result': None, 'ratelimit_result': None
    }

    logger.info("=== Memulai SCAN ALL ===")
    zap_url, nmap_host = normalize_targets(raw_url_input)
    
    # 1. Injection
    if args.xss_enabled:
        t0 = time.time()
        inj_res = run_xss_sqli(zap_url)
        results['xss_results'] = inj_res.get('xss_results', [])
        results['sqli_results'] = inj_res.get('sqli_results', [])
        logger.info(f"[TIME] Injection: {time.time()-t0:.2f}s")
    else:
        logger.info("[SKIP] Injection disabled")

    # 2. Parallel Recon
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_tech = executor.submit(run_tech_detector, zap_url) if args.tech_enabled else None

        future_nmap = None
        if args.nmap_enabled:
            nmap_params = {
                'ports_option': args.nmap_ports,
                'specific_ports_str': args.nmap_specific_ports,
                'show_os': args.nmap_show_os,
                'show_service': args.nmap_show_service
            }
            future_nmap = executor.submit(run_nmap_scan, nmap_host, nmap_params)

        future_ssl = executor.submit(run_ssl_scan, zap_url) if args.ssl_enabled else None

        # Collect
        tech_list = []
        if future_tech:
            tech_data = future_tech.result()
            tech_list = tech_data.get('tech', [])

        if future_nmap:
            nmap_data = future_nmap.result().get('nmap_result')
            results['nmap_result'] = nmap_data
            if nmap_data and 'open_ports' in nmap_data:
                for p in nmap_data['open_ports']:
                    if p.get('service') and p.get('version'):
                        svc_str = f"{p['service']} {p['version']}"
                        if svc_str not in tech_list: tech_list.append(svc_str)

        if future_ssl:
            ssl_data = future_ssl.result()
            results['ssl_result'] = ssl_data
    # 3. CVE
    results['tech'] = tech_list
    # CVE: hanya jalankan jika tech_enabled
    if args.tech_enabled:
        logger.info("[CVE] Searching CVEs...")
        if tech_list:
            results['cves'] = search_cves_list(tech_list)
        else:
            results['cves'] = []  # Tech dijalankan tapi tidak ada teknologi ditemukan
    else:
        # Tech tidak dijalankan -> CVE juga None
        results['tech'] = None
        results['cves'] = None

    logger.info(f"[RESULT] Tech={results['tech']}, CVE={results['cves']}")

     # 4. ZAP
    if args.zap_enabled:
        t0 = time.time()
        zap_res = run_zap(zap_url)
        results['zap_alerts'] = zap_res.get('zap_alerts', [])
        logger.info(f"[TIME] ZAP: {time.time()-t0:.2f}s")
    else:
        logger.info("[SKIP] ZAP disabled")

    # 5. Rate Limit
    if ratelimit_level > 0:
        t0 = time.time()
        results['ratelimit_result'] = run_rate_limit_test(zap_url, ratelimit_level)
        logger.info(f"[TIME] Rate Limit: {time.time()-t0:.2f}s")
    else:
        logger.info("[SKIP] Rate Limit disabled")

    # --- SCORING FINAL ---
    
    # A. Score CVE
    final_cve_score = None
    if results['cves'] is not None:
        cvss_list = [cve.get("cvss_score") for cve in results['cves'] if cve.get("cvss_score") is not None]
        final_cve_score = cvss_to_score(cvss_list)

    # B. Score Config (ZAP + SSL + Nmap)
    final_zap_score = None
    # PERBAIKAN: Cek apakah ada test config yang BENAR-BENAR dijalankan
    config_tests_run = (
        results['zap_alerts'] is not None or 
        results['ssl_result'] is not None or 
        results['nmap_result'] is not None
    )
    if config_tests_run:
        score_base = zap_to_score(results['zap_alerts'], results['ssl_result'])
        score_nmap = nmap_to_score(results['nmap_result'])
        final_zap_score = min(score_base, score_nmap)

    # C. Final Aggregation
    valid_scores = []
    if final_cve_score is not None: valid_scores.append(final_cve_score)
    if final_zap_score is not None: valid_scores.append(final_zap_score)
    
    if valid_scores:
        final_num = min(valid_scores)
        final_grade = score_to_grade(final_num)
    else:
        final_grade = "N/A"

    results['security_score'] = {
        "cve_score": score_to_grade(final_cve_score) if final_cve_score is not None else "N/A",
        "zap_score": score_to_grade(final_zap_score) if final_zap_score is not None else "N/A",
        "final_score": final_grade
    }
    
    # Metadata Status
    impact_label = analyze_impact_sentiment(results)
    count_zap = len(results['zap_alerts'] or []) if results['zap_alerts'] is not None else 0
    count_cve = len(results['cves'] or [])
    count_xss = len(results['xss_results'] or [])
    count_sqli = len(results['sqli_results'] or [])
    total_findings = count_zap + count_cve + count_xss + count_sqli
    
    # Tambahkan temuan Nmap critical ke total findings
    if results.get('nmap_result') and results['nmap_result'].get('open_ports'):
        for p in results['nmap_result']['open_ports']:
             if p.get('risk') in ['Critical', 'High']: total_findings += 1

    results['impact_analysis'] = {
        "label": impact_label,
        "summary": f"Total {total_findings} temuan signifikan. Status Akhir: {impact_label}"
    }

    try: shutdown_zap()
    except: pass

    elapsed_sec = time.time() - start_time
    if elapsed_sec < 60:
        time_str = f"{elapsed_sec:.1f} detik"
    else:
        minutes = int(elapsed_sec // 60)
        seconds = int(elapsed_sec % 60)
        time_str = f"{minutes} menit {seconds} detik"
    
    results['scan_metadata'] = {
        'execution_time': time_str,
        'execution_time_seconds': elapsed_sec
    }
    
    sys.stdout = original_stdout
    print(json.dumps(results, indent=2, ensure_ascii=False))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('url')
    parser.add_argument('--tech_enabled', action='store_true')
    parser.add_argument('--xss_enabled', action='store_true')
    parser.add_argument('--zap_enabled', action='store_true')
    parser.add_argument('--ssl_enabled', action='store_true')
    parser.add_argument('--nmap_enabled', action='store_true')
    parser.add_argument('--nmap_ports', type=str, default='top1000')
    parser.add_argument('--nmap_specific_ports', type=str, default='')
    parser.add_argument('--nmap_show_os', action='store_true')
    parser.add_argument('--nmap_show_service', action='store_true')
    parser.add_argument('--ratelimit_level', type=int, default=0) 
    parser.add_argument('--cookie', type=str, default='')
    # Dummy args
    parser.add_argument('--dos_enabled', action='store_true') 
    parser.add_argument('--requests_num', type=str) 
    parser.add_argument('--duration', type=str) 
    parser.add_argument('--packet_size', type=str) 
    parser.add_argument('--connections_per_page', type=str) 
    parser.add_argument('--dos_method', type=str) 
    parser.add_argument('--sod', action='store_true') 

    args = parser.parse_args()
    if args.dos_enabled and args.ratelimit_level == 0: args.ratelimit_level = 1

    main_scan(args.url, args, ratelimit_level=args.ratelimit_level)