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
import traceback

# --- TRICK: REDIRECT STDOUT TO STDERR GLOBALLY ---
# Agar output print() biasa tidak mengotori hasil JSON di akhir
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

# --- WRAPPERS (Jembatan ke Modul Lain) ---
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

def run_ssl_scan_wrapper(target_url):
    """Wrapper untuk run_ssl_scan dengan logging dan fallback error object"""
    logger.info(f"[SSL WRAPPER] start -> {target_url}")
    try:
        # pastikan run_ssl_scan tersedia
        if 'run_ssl_scan' not in globals() or run_ssl_scan is None:
            raise RuntimeError("run_ssl_scan function not available")
        res = run_ssl_scan(target_url)
        logger.info(f"[SSL WRAPPER] success -> type={type(res)}")
        # normalisasi: pastikan dict
        if res is None:
            return {"error": "No result (None)"}
        if not isinstance(res, dict):
            return {"result": res}
        return res
    except Exception as e:
        logger.error(f"[SSL WRAPPER] exception: {e}")
        logger.error(traceback.format_exc())
        return {"error": f"SSL scan failed: {str(e)}"}

# --- SCIENTIFIC SCORING FUNCTIONS (CVSS & WEAKEST LINK) ---

def normalize_risk_to_cvss(risk_level_str):

    risk = str(risk_level_str).lower()
    if 'critical' in risk: return 9.5  
    if 'high' in risk: return 8.0     
    if 'medium' in risk: return 5.5    
    if 'low' in risk: return 2.5       
    return 0.0                        

def calculate_aggregated_risk(results):
    max_severity_score = 0.0
    findings_summary = []

    # 1. Analisis CVE (NVD) - Sudah berupa angka CVSS
    cves = results.get('cves') or []
    if cves:
        for cve in cves:
            try:
                score = float(cve.get('cvss_score', 0))
                if score > max_severity_score:
                    max_severity_score = score
            except: pass
        if max_severity_score > 0:
            findings_summary.append(f"Software Vulnerability (CVE Max: {max_severity_score})")

    # 2. Analisis ZAP Alerts - Konversi Kualitatif ke Kuantitatif
    zap_alerts = results.get('zap_alerts') or []
    if zap_alerts:
        local_max = 0.0
        for alert in zap_alerts:
            risk_str = alert.get('risk', '')
            score = normalize_risk_to_cvss(risk_str)
            if score > local_max: local_max = score
        
        if local_max > max_severity_score:
            max_severity_score = local_max
        if local_max > 0:
            findings_summary.append(f"Web Vulnerability (ZAP Max Risk: {local_max})")

    # 3. Analisis SSL/TLS - Hardcoded Severity berdasarkan Best Practice
    ssl_data = results.get('ssl_result')
    if ssl_data and isinstance(ssl_data, dict) and 'error' not in ssl_data:
        local_max = 0.0
        vulns = ssl_data.get('vulnerabilities', [])
        weak_ciphers = ssl_data.get('weak_ciphers', [])
        
        # Critical SSL Issues (Heartbleed, POODLE, SSLv2/3) -> CVSS 9.0+
        for v in vulns:
            if "SSLv2" in v or "SSLv3" in v or "Critical" in v:
                local_max = max(local_max, 9.5)
        
        # Weak Configuration (TLS 1.0/1.1) -> CVSS 5.0 (Medium)
        if not local_max and weak_ciphers:
            local_max = max(local_max, 5.0)
            
        if local_max > max_severity_score:
            max_severity_score = local_max
        if local_max > 0:
            findings_summary.append(f"SSL/TLS Config Issue (Score: {local_max})")

    # 4. Analisis Rate Limit - Availability Impact (High)
    rl_data = results.get('ratelimit_result')
    if rl_data and isinstance(rl_data, dict):
        summary = str(rl_data.get('summary', '')).upper()
        # Jika summary mengandung kata 'RENTAN' atau 'VULNERABLE', anggap High Risk
        if 'RENTAN' in summary or 'VULNERABLE' in summary:
            score = 7.5
            if score > max_severity_score:
                max_severity_score = score
            findings_summary.append(f"Rate Limit Vulnerability (Score: {score})")

    # 5. Analisis Injection (XSS/SQLi) - High/Critical Impact
    xss_count = len(results.get('xss_results') or [])
    sqli_count = len(results.get('sqli_results') or [])
    
    if xss_count > 0 or sqli_count > 0:
        # SQLi/XSS Validated -> Critical/High
        score = 8.5
        if score > max_severity_score:
            max_severity_score = score
        findings_summary.append(f"Injection Exploit Verified (SQLi/XSS) (Score: {score})")

    # 6. Analisis Nmap - Risky Ports
    nmap_data = results.get('nmap_result')
    if nmap_data and isinstance(nmap_data, dict):
        open_ports = nmap_data.get('open_ports', [])
        local_max = 0.0
        for p in open_ports:
            risk = p.get('risk', '')
            if risk == 'Critical': local_max = max(local_max, 9.0)
            elif risk == 'High': local_max = max(local_max, 7.5)
        
        if local_max > max_severity_score:
            max_severity_score = local_max

    return max_severity_score, list(set(findings_summary))

def get_letter_grade(max_cvss_score):
    """
    Menentukan Nilai Huruf berdasarkan Skor Risiko Tertinggi (CVSS).
    Makin tinggi CVSS -> Makin buruk nilai hurufnya.
    """
    if max_cvss_score >= 9.0: return "F"  # Critical Risk
    if max_cvss_score >= 7.0: return "D"  # High Risk
    if max_cvss_score >= 4.0: return "C"  # Medium Risk
    if max_cvss_score > 0.0:  return "B"  # Low Risk
    return "A"                            # Secure / No Findings

# --- MAIN ORCHESTRATOR ---
def main_scan(raw_url_input, args, ratelimit_level=0):
    start_time = time.time()
    results = {
        'tech': None, 'cves': None, 'zap_alerts': None, 'xss_results': None, 
         'sqli_results': None, 'nmap_result': None, 'ssl_result': None, 'ratelimit_result': None
    }

    logger.info("=== Memulai SCAN ALL ===")
    zap_url, nmap_host = normalize_targets(raw_url_input)
    
    # 1. Injection
    if args.xss_enabled:
        t0 = time.time()
        try:
            inj_res = run_xss_sqli(zap_url)
            results['xss_results'] = inj_res.get('xss_results', [])
            results['sqli_results'] = inj_res.get('sqli_results', [])
        except Exception: results['xss_results'] = [] # Fail safe
        logger.info(f"[TIME] Injection: {time.time()-t0:.2f}s")
    else:
        logger.info("[SKIP] Injection disabled")

    # 2. Parallel Recon (Tech, NMAP, SSL)
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

        future_ssl = executor.submit(run_ssl_scan_wrapper, zap_url) if args.ssl_enabled else None

        # Collect results
        tech_list = []
        if future_tech:
            tech_data = future_tech.result()
            tech_list = tech_data.get('tech', [])
            results['tech'] = tech_list

        if future_nmap:
            nmap_data = future_nmap.result().get('nmap_result')
            results['nmap_result'] = nmap_data
            if nmap_data and 'open_ports' in nmap_data:
                for p in nmap_data['open_ports']:
                    if p.get('service') and p.get('version'):
                        svc_str = f"{p['service']} {p['version']}"
                        if svc_str not in tech_list: tech_list.append(svc_str)

        if future_ssl:
            logger.info("[SSL] waiting for future_ssl result...")
            try:
                ssl_data = future_ssl.result()
                results['ssl_result'] = ssl_data
                logger.info(f"[SSL] Complete: {ssl_data}")
            except Exception as e:
                logger.error(f"[SSL] future_ssl raised exception: {e}")
                logger.error(traceback.format_exc())
                results['ssl_result'] = {"error": str(e)}
        else:
            logger.info("[SSL] not requested / future_ssl is None")
            results['ssl_result'] = None

    # 3. CVE - only if tech_enabled
    if args.tech_enabled:
        logger.info("[CVE] Searching CVEs...")
        if tech_list:
            results['cves'] = search_cves_list(tech_list)
        else:
            results['cves'] = []
    else:
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

    # 5. Rate Limit (DENGAN TRY-EXCEPT UNTUK MENCEGAH CRASH TOTAL)
    if ratelimit_level > 0:
        t0 = time.time()
        try:
            results['ratelimit_result'] = run_rate_limit_test(zap_url, ratelimit_level)
        except Exception as e:
            logger.error(f"Rate Limit Failed: {e}")
            results['ratelimit_result'] = {"error": f"Test Gagal: {str(e)}", "summary": "Gagal Menjalankan Tes"}
        logger.info(f"[TIME] Rate Limit: {time.time()-t0:.2f}s")
    else:
        logger.info("[SKIP] Rate Limit disabled")

    # --- SCORING FINAL (SCIENTIFIC APPROACH) ---
    try:
        # Hitung Agregasi Risiko (Prinsip Weakest Link)
        max_risk, risk_drivers = calculate_aggregated_risk(results)
        
        # Hitung Nilai Kesehatan Sistem (Skala 0 - 100)
        # Rumus Inverse: 100 - (CVSS Tertinggi * 10). 
        # Contoh: Jika ada Critical (9.5), Health = 100 - 95 = 5.
        health_score = max(0, 100 - (max_risk * 10))
        
        # Tentukan Huruf Mutu (A-F)
        final_grade = get_letter_grade(max_risk)

        results['security_score'] = {
            "max_risk_cvss": round(max_risk, 1),
            "health_score_100": int(health_score),
            "final_score": final_grade, # INI YANG DIBACA FRONTEND SEBAGAI GRADE
            "risk_drivers": risk_drivers
        }
        
        # Human Readable Summary (Updated Format)
        risk_str = f"{max_risk:.1f}"
        
        # Format: "Skor Akhir: 9.8 (Grade F). ..."
        summary_text = f"Skor Akhir: {risk_str} (Grade {final_grade}). "
        
        if risk_drivers: 
            summary_text += f"Ditemukan risiko tertinggi dengan skor CVSS {risk_str}. Faktor Utama: {', '.join(risk_drivers[:3])}"
        else: 
            summary_text += "Sistem relatif aman. Tidak ditemukan kerentanan signifikan."

        results['impact_analysis'] = {
            "label": final_grade,
            "summary": summary_text
        }

    except Exception as e:
        logger.error(f"Scoring Error: {e}")
        logger.error(traceback.format_exc())
        # Fallback jika scoring gagal agar tidak 'undefined' di frontend
        results['security_score'] = {
            "final_score": "ERR",
            "max_risk_cvss": 0,
            "health_score_100": 0
        }
        results['impact_analysis'] = {"summary": f"Gagal menghitung skor: {str(e)}"}

    try: 
        shutdown_zap()
    except: 
        pass

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
    
    # Kembalikan output ke stdout asli untuk dicetak sebagai JSON bersih
    sys.stdout = original_stdout
    print(json.dumps(results, indent=2, ensure_ascii=False))

if __name__ == "__main__":
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
    parser.add_argument('--dos_enabled', action='store_true') 
    parser.add_argument('--requests_num', type=str) 
    parser.add_argument('--duration', type=str) 
    parser.add_argument('--packet_size', type=str) 
    parser.add_argument('--connections_per_page', type=str) 
    parser.add_argument('--dos_method', type=str) 
    parser.add_argument('--sod', action='store_true') 

    args = parser.parse_args()
    
    logger.info(f"[DEBUG] sys.argv: {sys.argv}")
    logger.info(f"[DEBUG] parsed args: {args}")
    logger.info(f"[DEBUG] ssl_enabled: {args.ssl_enabled}")
    
    if args.dos_enabled and args.ratelimit_level == 0: 
        args.ratelimit_level = 1

    main_scan(args.url, args, ratelimit_level=args.ratelimit_level)