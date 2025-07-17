from pathlib import Path
import subprocess
import json
import sys
import logging
import argparse
import concurrent.futures
from dosTester import run_dos_attack
from ZAPScanner import start_zap_daemon, wait_for_zap, run_zap_scan, hybrid_zap_scan
from techDetector import detect_software, search_cves_list
from xss_sqli_tester import detect_form, test_injection, xss_payloads, sqli_payloads
from datetime import datetime

log_file = Path(__file__).resolve().parent / 'scan_all.log'

logger = logging.getLogger("scan_all")
logger.setLevel(logging.DEBUG)
if logger.hasHandlers():
    logger.handlers.clear()
file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setLevel(logging.DEBUG)
stream_handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

def extract_json(stdout):
    import re, json
    match = re.search(r'({.*})', stdout, re.DOTALL)
    if match:
        return json.loads(match.group(1))
    return {}

def run_tech_detector(target_url):
    logger.info("[1] Deteksi teknologi dan CVE...")
    techs = detect_software(target_url)
    cves = search_cves_list(techs)
    return {
        'tech': techs,
        'cves': cves
    }

def run_xss_sqli(target_url):
    logger.info("[2] Pengujian XSS dan SQL Injection...")
    xss_results = []
    sqli_results = []
    forms = detect_form(target_url)
    for form in forms:
        method = form.get('method', 'get')
        action = form.get('action', target_url)
        inputs = form.get('inputs', [])
        xss_results.extend(test_injection(target_url, method, action, inputs, xss_payloads, type='xss'))
        sqli_results.extend(test_injection(target_url, method, action, inputs, sqli_payloads, type='sqli'))
    return {
        'xss_results': xss_results,
        'sqli_results': sqli_results
    }

def run_zap(target_url):
    logger.info("[3] Menjalankan/memastikan ZAP daemon & scanning...")
    zap_data = hybrid_zap_scan(target_url)
    alerts = []
    if zap_data and 'categories' in zap_data:
        for cat in zap_data['categories'].values():
            alerts.extend(cat.get('alerts', []))
    elif zap_data and 'error' in zap_data:
        logger.error(f"ZAP scan error: {zap_data['error']}")
    else:
        logger.error("ZAP scan returned no data.")
    return {'zap_alerts': alerts}

def cvss_to_score(cvss_list):
    if not cvss_list:
        return 5  # A
    max_cvss = max([s for s in cvss_list if s is not None] or [0])
    if max_cvss >= 9:
        return 1  # E
    elif max_cvss >= 7:
        return 2  # D
    elif max_cvss >= 4:
        return 3  # C
    elif max_cvss > 0:
        return 4  # B
    else:
        return 5  # A

def zap_to_score(zap_alerts):
    risks = [a.get('risk', '').lower() for a in zap_alerts]
    if 'high' in risks:
        return 1  # E
    elif 'medium' in risks:
        return 2  # D
    elif 'low' in risks:
        return 3  # C
    elif 'informational' in risks:
        return 4  # B
    else:
        return 5  # A

def score_to_grade(score):
    return {1: 'E', 2: 'D', 3: 'C', 4: 'B', 5: 'A'}[score]

def get_cve_date(cve):
    # Gunakan published, fallback ke lastModified, fallback ke ""
    date_str = cve.get("published") or cve.get("lastModified") or ""
    try:
        # Format ISO 8601, contoh: "2024-07-01T15:15:05.000"
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except Exception:
        return datetime.min

def main_scan(target_url, dos_params=None):
    results = {
        'tech': [],
        'cves': [],
        'zap_alerts': [],
        'xss_results': [],
        'sqli_results': [],
        'dos_summary': ''
    }

    logger.info("=== Memulai SCAN ALL ===")
    logger.info(f"Target: {target_url}")

    # Jalankan TechDetector, XSS/SQLi, dan ZAP secara paralel
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_tech = executor.submit(run_tech_detector, target_url)
        future_xss = executor.submit(run_xss_sqli, target_url)
        future_zap = executor.submit(run_zap, target_url)

        # Tunggu semua selesai
        tech_result = future_tech.result()
        xss_result = future_xss.result()
        zap_result = future_zap.result()

    # Gabungkan hasil
    results['tech'] = tech_result.get('tech', [])
    results['cves'] = tech_result.get('cves', [])
    results['xss_results'] = xss_result.get('xss_results', [])
    results['sqli_results'] = xss_result.get('sqli_results', [])
    results['zap_alerts'] = zap_result.get('zap_alerts', [])
    if 'zap_error' in zap_result:
        results['zap_error'] = zap_result['zap_error']

    logger.info(f"   • Teknologi terdeteksi: {results['tech']}")
    logger.info(f"   • Total CVE ditemukan: {len(results['cves'])}")
    logger.info(f"   • XSS ditemukan: {len(results['xss_results'])}")
    logger.info(f"   • SQLi ditemukan: {len(results['sqli_results'])}")
    logger.info(f"   • ZAP Alerts: {len(results['zap_alerts'])}")

    # DoS test (jalankan terakhir, sinkron)
    if dos_params:
        try:
            logger.info("[4] Menjalankan DoS test...")
            dos_result = run_dos_attack(target_url, **dos_params)
            results['dos_summary'] = dos_result.get("summary", "")
            results['dos_timeline'] = dos_result.get("timeline", [])
            results['dos_down_at'] = dos_result.get("down_at", None)
            logger.info(f"   • DoS summary: {results['dos_summary']}")
        except Exception as e:
            results['dos_summary'] = f"Gagal menjalankan DoS: {e}"
            results['dos_timeline'] = []
            results['dos_down_at'] = None
            logger.error(results['dos_summary'])

    # --- Summary ---
    logger.info("=== SCAN ALL SUMMARY ===")
    logger.info(f"   • Teknologi: {results['tech']}")
    logger.info(f"   • CVE: {len(results['cves'])}")
    logger.info(f"   • XSS: {len(results['xss_results'])}")
    logger.info(f"   • SQLi: {len(results['sqli_results'])}")
    logger.info(f"   • ZAP Alerts: {len(results['zap_alerts'])}")
    logger.info(f"   • DoS: {results.get('dos_summary', '')}")

    # Penilaian keamanan
    cvss_scores = [cve.get("cvss_score") for cve in results['cves'] if cve.get("cvss_score") is not None]
    score_cve = cvss_to_score(cvss_scores)
    score_zap = zap_to_score(results['zap_alerts'])
    final_score = min(score_cve, score_zap)
    final_grade = score_to_grade(final_score)
    results['security_score'] = {
        "cve_score": score_to_grade(score_cve),
        "zap_score": score_to_grade(score_zap),
        "final_score": final_grade
    }
    results['cves'] = sorted(results['cves'], key=get_cve_date, reverse=True)
    print(json.dumps(results, indent=2, ensure_ascii=False))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('url', help='Target URL')
    parser.add_argument('--dos_enabled', action='store_true')
    parser.add_argument('--requests_num', type=int, default=100)
    parser.add_argument('--duration', type=int, default=10)
    parser.add_argument('--packet_size', type=int, default=1024)
    parser.add_argument('--connections_per_page', type=int, default=100)  # Tambahkan ini
    parser.add_argument('--dos_method', type=str, default='slowloris')    # Tambahkan ini
    parser.add_argument('--sod', action='store_true', help='Stop on Down (hentikan DoS jika server down)')
    args = parser.parse_args()

    dos_params = None
    if args.dos_enabled:
        dos_params = {
            'requests_num': args.requests_num,
            'duration': args.duration,
            'packet_size': args.packet_size,
            'connections_per_page': args.connections_per_page,
            'method': args.dos_method,
            'stop_on_down': args.sod
        }
    main_scan(args.url, dos_params)
