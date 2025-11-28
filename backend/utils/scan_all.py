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

# --- TRICK: REDIRECT STDOUT ---
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
    from ZAPScanner import execute_zap_scan, kill_zap
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
    logger.info(f"[NMAP] Target: {nmap_host} | Params: {nmap_params}")
    try:
        # 1. Parsing specific ports manual
        specific_ports = None
        port_str = nmap_params.get('specific_ports_str', '')
        if nmap_params.get('ports_option') == 'specific' and port_str:
            try:
                specific_ports = [int(p.strip()) for p in port_str.split(',') if p.strip().isdigit()]
            except:
                logger.warning("Format port spesifik salah, fallback ke top1000")
                nmap_params['ports_option'] = 'top1000'

        # 2. Panggil run_nmap dengan argumen eksplisit
        timeout = 1800 if nmap_params.get('ports_option') == 'all' else 600
        
        result = run_nmap(
            target=nmap_host,
            ports_option=nmap_params.get('ports_option', 'top1000'),
            specific_ports=specific_ports,
            show_os=nmap_params.get('show_os', False),
            show_service=nmap_params.get('show_service', True),
            timeout=timeout
        )
        return {'nmap_result': result}
    except Exception as e:
        logger.error(f"Nmap Critical Error: {e}")
        return {'nmap_result': {'error': str(e)}}

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
        for form in forms:
            method = form.get('method', 'get')
            action = form.get('action', target_url)
            inputs = form.get('inputs', [])
            xss_results.extend(test_injection(target_url, method, action, inputs, xss_payloads, type='xss'))
            sqli_results.extend(test_injection(target_url, method, action, inputs, sqli_payloads, type='sqli'))
        return {'xss_results': xss_results, 'sqli_results': sqli_results}
    except:
        return {'xss_results': [], 'sqli_results': []}

def run_zap(target_url):
    logger.info("[ZAP] Running Hybrid Scan...")
    all_alerts = []
    try:
        # 1. ZAP Passive & Spider (FIXED: HAPUS enable_active_scan)
        # Parameter enable_active_scan dihapus karena ZAPScanner.py sudah tidak menerimanya
        zap_data = execute_zap_scan(
            target_url, 
            max_depth=2, 
            selenium_only=False, 
            traditional_only=False
        )
        
        if zap_data and 'categories' in zap_data:
            for cat in zap_data['categories'].values():
                all_alerts.extend(cat.get('alerts', []))
                
        # 2. Custom Active Scan
        logger.info("[ZAP] Running Custom Active Scan...")
        custom_alerts = run_custom_scan(target_url)
        all_alerts.extend(custom_alerts)
        
    except Exception as e:
        logger.error(f"ZAP/Custom Error: {e}")
        
    return {'zap_alerts': all_alerts}

# --- SCORING ---
def cvss_to_score(cvss_list):
    if not cvss_list: return 100
    try:
        max_cvss = max(cvss_list)
        return max(0, 100 - (max_cvss * 10))
    except: return 0

def zap_to_score(alerts, ssl_data=None):
    if not alerts and not ssl_data: return 100
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

def score_to_grade(score):
    try: s = float(score)
    except: return "N/A"
    if s >= 90: return "A"
    if s >= 75: return "B"
    if s >= 60: return "C"
    if s >= 40: return "D"
    return "F"

def analyze_impact_sentiment(results):
    # Cek apakah ada test yang dijalankan (selain None)
    run_check = [
        results.get('zap_alerts'), 
        results.get('cves'), 
        results.get('xss_results'),
        results.get('ssl_result'),
        results.get('nmap_result')
    ]
    # Jika semua None, berarti tidak ada test yang dijalankan
    if all(x is None for x in run_check):
        return "TIDAK ADA TEST DIJALANKAN"
        
    score = 0
    if results.get('sqli_results') and len(results['sqli_results']) > 0: score += 50
    if results.get('xss_results') and len(results['xss_results']) > 0: score += 30

    if results.get('cves'):
        for cve in results['cves']:
            cvss = cve.get('cvss_score', 0)
            if cvss >= 9.0: score += 20
            elif cvss >= 7.0: score += 10
            elif cvss >= 4.0: score += 5
            else: score += 1

    if results.get('zap_alerts'):
        for alert in results['zap_alerts']:
            risk = str(alert.get('risk', '')).lower()
            if 'high' in risk or 'critical' in risk: score += 10
            elif 'medium' in risk: score += 5
            elif 'low' in risk: score += 1
    
    if results.get('ratelimit_result'):
        rl = results['ratelimit_result']
        if "RENTAN" in rl.get('summary', ''): score += 10

    if score >= 50: return "🚨 KRITIS (Bahaya Injeksi/Eksploitasi Aktif)"
    elif score >= 20: return "⚠️ BERISIKO TINGGI (CVE/Isu High Ditemukan)"
    elif score >= 10: return "🚧 PERINGATAN (Perlu Perbaikan)"
    elif score >= 1: return "ℹ️ INFO (Isu Ringan)"
    else: return "✅ AMAN (Tidak Ada Isu Terdeteksi)"

# --- MAIN ORCHESTRATOR ---
def main_scan(raw_url_input, args, ratelimit_level=0):
    results = {
        'tech': [], 'cves': [], 
        'zap_alerts': None, 'xss_results': None, 'sqli_results': None, 
        'nmap_result': None, 'ssl_result': None, 'ratelimit_result': None
    }

    logger.info("=== Memulai SCAN ALL ===")
    zap_url, nmap_host = normalize_targets(raw_url_input)
    
    # 1. Injection
    if args.xss_enabled:
        t0 = time.time()
        inj_res = run_xss_sqli(zap_url)
        results['xss_results'] = inj_res.get('xss_results', [])
        results['sqli_results'] = inj_res.get('sqli_results', [])
        logger.info(f"[TIME] Injection selesai: {time.time()-t0:.2f}s")
    else:
        logger.info("[SKIP] Injection test disabled")

    # 2. Recon (Parallel)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_tech = None
        if args.tech_enabled:
            future_tech = executor.submit(run_tech_detector, zap_url)
        else:
            logger.info("[SKIP] Tech detection disabled")
        
        future_nmap = None
        if args.nmap_enabled:
            nmap_params = {
                'ports_option': args.nmap_ports,
                'specific_ports_str': args.nmap_specific_ports,
                'show_os': args.nmap_show_os,
                'show_service': args.nmap_show_service
            }
            future_nmap = executor.submit(run_nmap_scan, nmap_host, nmap_params)
        else:
            logger.info("[SKIP] Nmap disabled")
            
        future_ssl = None
        if args.ssl_enabled:
            future_ssl = executor.submit(run_ssl_scan, zap_url)
        else:
            logger.info("[SKIP] SSL disabled")

        # Collect
        tech_list = []
        if future_tech:
            tech_data = future_tech.result()
            tech_list = tech_data.get('tech', [])
        
        if future_nmap:
            nmap_res = future_nmap.result()
            nmap_data = nmap_res.get('nmap_result')
            results['nmap_result'] = nmap_data
            if nmap_data and 'open_ports' in nmap_data:
                for p in nmap_data['open_ports']:
                    if p.get('service') and p.get('version'):
                        svc_str = f"{p['service']} {p['version']}"
                        if svc_str not in tech_list: tech_list.append(svc_str)
                            
        if future_ssl:
            results['ssl_result'] = future_ssl.result()

    # 3. CVE Enrichment
    results['tech'] = tech_list
    if args.tech_enabled and tech_list:
        logger.info("[CVE] Searching CVEs...")
        results['cves'] = search_cves_list(tech_list)
    else:
        # Jika tech detector dijalankan tapi tidak nemu apa-apa -> list kosong (Aman)
        # Jika tech detector TIDAK dijalankan -> None
        results['cves'] = [] if args.tech_enabled else None

    # 4. ZAP (Hybrid)
    if args.zap_enabled:
        t0 = time.time()
        zap_res = run_zap(zap_url)
        results['zap_alerts'] = zap_res.get('zap_alerts', [])
        logger.info(f"[TIME] ZAP selesai: {time.time()-t0:.2f}s")
    else:
        logger.info("[SKIP] ZAP disabled")

    # 5. Rate Limit
    if ratelimit_level > 0:
        t0 = time.time()
        results['ratelimit_result'] = run_rate_limit_test(zap_url, ratelimit_level)
        logger.info(f"[TIME] Rate Limit selesai: {time.time()-t0:.2f}s")
    else:
        logger.info("[SKIP] Rate Limit disabled")

    # ANALISIS & SCORING
    impact_label = analyze_impact_sentiment(results)
    
    total_findings = (len(results['cves'] or []) + len(results['zap_alerts'] or []) + len(results['xss_results'] or []) + len(results['sqli_results'] or []))
    
    results['impact_analysis'] = {
        "label": impact_label,
        "summary": f"Total {total_findings} temuan. Status Akhir: {impact_label}"
    }

    cvss_list = [cve.get("cvss_score") for cve in (results['cves'] or []) if cve.get("cvss_score") is not None]
    score_cve = cvss_to_score(cvss_list)
    score_zap = zap_to_score(results['zap_alerts'], results['ssl_result'])
    final_score = min(score_cve, score_zap)
    
    results['security_score'] = {
        "cve_score": score_to_grade(score_cve),
        "zap_score": score_to_grade(score_zap),
        "final_score": score_to_grade(final_score)
    }
    
    try: kill_zap()
    except: pass

    sys.stdout = original_stdout
    print(json.dumps(results, indent=2, ensure_ascii=False))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('url')
    # Flags
    parser.add_argument('--tech_enabled', action='store_true')
    parser.add_argument('--xss_enabled', action='store_true')
    parser.add_argument('--zap_enabled', action='store_true')
    parser.add_argument('--ssl_enabled', action='store_true')
    parser.add_argument('--nmap_enabled', action='store_true')
    
    # Nmap Args
    parser.add_argument('--nmap_ports', type=str, default='top1000')
    parser.add_argument('--nmap_specific_ports', type=str, default='')
    parser.add_argument('--nmap_show_os', action='store_true')
    parser.add_argument('--nmap_show_service', action='store_true')
    
    # Rate Limit Args
    parser.add_argument('--ratelimit_level', type=int, default=0) 
    parser.add_argument('--cookie', type=str, default='')

    args = parser.parse_args()
    main_scan(args.url, args, ratelimit_level=args.ratelimit_level)