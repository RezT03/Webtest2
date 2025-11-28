import subprocess
import logging
import time
import requests
import json
import sys
import os
import argparse
import platform
from urllib.parse import urlparse

# --- DRISSIONPAGE IMPORT ---
try:
    from DrissionPage import ChromiumPage, ChromiumOptions
except ImportError:
    sys.stderr.write("[-] DrissionPage not found. Install with: pip install DrissionPage\n")
    sys.exit(1)

from zapv2 import ZAPv2


# ================================
# ========= GLOBAL VARS ==========
# ================================

ZAP_PORT = 8090
ZAP_HOST = "127.0.0.1"
BASE_URL = f"http://{ZAP_HOST}:{ZAP_PORT}"

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))

ZAP_DIR_NAME = "ZAP_2.16.1"

if platform.system() == "Windows":
    ZAP_EXECUTABLE = "zap.bat"
else:
    ZAP_EXECUTABLE = "zap.sh"

ZAP_PATH = os.path.join(PROJECT_ROOT, ZAP_DIR_NAME, ZAP_EXECUTABLE)
ZAP_WORKING_DIR = os.path.join(PROJECT_ROOT, ZAP_DIR_NAME)

DEFAULT_MAX_SPIDER_TIME = 120
DEFAULT_MAX_CRAWL_DEPTH = 2

logger = logging.getLogger("ZAPScanner")
logger.setLevel(logging.INFO)
if not logger.hasHandlers():
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
    logger.addHandler(handler)

zap_process = None
page = None


# ================================
# ========= UTILITIES ============
# ================================

def log_msg(msg):
    logger.info(msg)


def save_results_to_json(scan_result, filename=None):
    if not scan_result:
        return None

    if not filename:
        try:
            target_domain = urlparse(scan_result["scan_info"].get("target_url", "unknown")).netloc
        except:
            target_domain = "unknown"

        timestamp = int(time.time())
        filename = f"zap_scan_result_{target_domain}_{timestamp}.json"

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(scan_result, f, indent=2, ensure_ascii=False)
        log_msg(f"[+] Hasil disimpan ke file: {filename}")
        return filename
    except Exception as e:
        log_msg(f"[-] Gagal menyimpan JSON: {e}")
        return None


def send_results_to_endpoint(scan_result, webhook_url=None):
    if not scan_result or not webhook_url:
        return False
    try:
        requests.post(webhook_url, json=scan_result, headers={'Content-Type': 'application/json'}, timeout=30)
        log_msg(f"[+] Hasil dikirim ke webhook: {webhook_url}")
        return True
    except Exception as e:
        log_msg(f"[-] Gagal kirim webhook: {e}")
        return False


# ================================
# ========= ZAP UTILITY ==========
# ================================

def java_exists():
    try:
        subprocess.check_output(["java", "-version"], stderr=subprocess.STDOUT)
        return True
    except Exception:
        return False


def get_zap_client():
    return ZAPv2(proxies={'http': BASE_URL, 'https': BASE_URL})


def is_zap_running():
    try:
        resp = requests.get(f"{BASE_URL}/JSON/core/view/version/", timeout=3)
        return resp.status_code == 200
    except:
        return False


def start_zap_daemon():
    global zap_process

    if is_zap_running():
        log_msg("[+] ZAP daemon sudah berjalan.")
        return True

    if not java_exists():
        log_msg("[-] Java tidak ditemukan! Install Java Runtime (JRE/JDK).")
        return False

    if not os.path.exists(ZAP_PATH):
        log_msg(f"[-] ERROR FATAL: File ZAP tidak ditemukan di {ZAP_PATH}")
        return False

    log_msg(f"[+] Menjalankan ZAP dari: {ZAP_PATH}")
    log_msg(f"[+] Working Directory: {ZAP_WORKING_DIR}")

    cmd = [
        ZAP_PATH,
        "-daemon",
        "-port", str(ZAP_PORT),
        "-host", ZAP_HOST,
        "-config", "api.disablekey=true",
        "-config", "api.addrs.addr.name=.*",
        "-config", "api.addrs.addr.regex=true"
    ]

    try:
        zap_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=ZAP_WORKING_DIR,   # FIX WAJIB UNTUK WINDOWS
            shell=True if platform.system() == "Windows" else False
        )
    except Exception as e:
        log_msg(f"[-] Tidak dapat menjalankan ZAP: {e}")
        return False

    log_msg("[+] Menunggu ZAP daemon siap... (maks 5 menit)")
    try:
        wait_for_zap(timeout=300)
        log_msg("[+] ZAP daemon berhasil dimulai.")
        return True
    except Exception as e:
        log_msg(f"[-] ZAP gagal start: {e}")
        kill_zap()
        return False


def kill_zap():
    global zap_process
    try:
        if zap_process and zap_process.poll() is None:
            zap_process.terminate()
            time.sleep(1)
            zap_process.kill()
            log_msg("[+] ZAP process dihentikan paksa.")
    except:
        pass


def wait_for_zap(timeout=180):
    start = time.time()
    while time.time() - start < timeout:
        if is_zap_running():
            return True
        time.sleep(3)
    raise Exception("Timeout: ZAP tidak merespon.")


def make_api_request(endpoint, params=None, timeout=30):
    if params is None:
        params = {}

    try:
        response = requests.get(f"{BASE_URL}{endpoint}", params=params, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        if "Read timed out" not in str(e):
            log_msg(f"[-] API Error {endpoint}: {e}")
        return None


# ================================
# ===== DrissionPage Utility =====
# ================================

def setup_drission_with_zap():
    global page
    log_msg("[+] Menginisialisasi DrissionPage...")

    try:
        co = ChromiumOptions()
        co.set_proxy(f"http://{ZAP_HOST}:{ZAP_PORT}")
        co.headless(True)
        co.set_argument('--no-sandbox')
        co.set_argument('--disable-gpu')
        co.set_argument('--mute-audio')
        co.set_argument('--ignore-certificate-errors')
        co.set_argument('--blink-settings=imagesEnabled=false')

        page = ChromiumPage(co)
        log_msg("[+] DrissionPage siap.")
        return True
    except Exception as e:
        log_msg(f"[-] Gagal inisialisasi DrissionPage: {e}")
        return False


def drission_crawl_and_interact(target_url, max_depth=2):
    log_msg("[+] Mulai crawling DrissionPage...")
    visited = set()
    to_visit = [target_url]
    forms = []

    for depth in range(max_depth):
        if not to_visit:
            break

        current_batch = to_visit.copy()
        to_visit = []

        for url in current_batch:
            if url in visited:
                continue

            try:
                page.get(url)
                visited.add(url)
                page.scroll.to_bottom()
                time.sleep(0.5)

                found_forms = page.eles('tag:form')
                for f in found_forms:
                    action = f.attr('action') or url
                    forms.append({'url': url, 'action': action})

                links = page.eles('tag:a')
                for l in links[:15]:
                    href = l.attr('href')
                    if href and href.startswith(target_url) and href not in visited:
                        to_visit.append(href)

            except:
                continue

    return visited, forms


def drission_form_interaction(forms_found):
    log_msg("[+] Mengisi form secara otomatis...")

    for form in forms_found[:5]:
        try:
            page.get(form['url'])
            inputs = page.eles('tag:input')

            for inp in inputs:
                if not inp.states.is_visible:
                    continue

                t = inp.attr('type')
                if t in ["text", "email", "search"]:
                    inp.input("zap_test")
                elif t == "password":
                    inp.input("P@ssw0rd123")

        except:
            pass


# ================================
# ========== ZAP SCAN ============
# ================================

def traditional_zap_scanning(target_url):
    log_msg("[+] Menjalankan Spider Scan...")

    endpoint = "/JSON/spider/action/scan/"
    params = {"url": target_url, "maxDuration": str(DEFAULT_MAX_SPIDER_TIME)}

    res = make_api_request(endpoint, params)

    if res and res.get('scan'):
        scan_id = res.get('scan')
        start = time.time()

        while True:
            if time.time() - start > DEFAULT_MAX_SPIDER_TIME + 10:
                break

            status = make_api_request("/JSON/spider/view/status/", {"scanId": scan_id})
            prog = status.get('status', '0')
            sys.stderr.write(f"\r    Spider: {prog}%")
            sys.stderr.flush()

            if prog == '100':
                break

            time.sleep(1)

    sys.stderr.write("\n")
    log_msg("[+] Menunggu passive scan...")

    while True:
        recs = make_api_request("/JSON/pscan/view/recordsToScan/")
        count = int(recs.get('recordsToScan', 0))

        if count == 0:
            break

        sys.stderr.write(f"\r    Queue: {count}")
        sys.stderr.flush()
        time.sleep(1)

    log_msg("[+] Passive scan selesai.")


def get_comprehensive_alerts(target_url=None):
    log_msg("[+] Mengambil report dari ZAP...")

    raw = make_api_request("/JSON/core/view/alerts/")
    if not raw:
        return None

    alerts = raw.get('alerts', [])
    filtered_alerts = []
    target_domain = ""

    if target_url:
        try:
            target_domain = urlparse(target_url).netloc.split(':')[0]
            if target_domain.startswith("www."):
                target_domain = target_domain[4:]
        except:
            pass

    waf_signatures = ["/cdn-cgi/", "/akam/", "/_Incapsula_", "/sucuri-firewall-block/", "/__utm"]

    for alert in alerts:
        alert_url = alert.get('url', '')

        if target_domain:
            try:
                ahost = urlparse(alert_url).netloc.split(':')[0]
                if not ahost.endswith(target_domain):
                    continue
            except:
                continue

        if any(sig in alert_url for sig in waf_signatures):
            continue

        filtered_alerts.append(alert)

    categories = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    for a in filtered_alerts:
        risk = a.get('risk', 'Informational')
        categories[risk] = categories.get(risk, 0) + 1

    result = {
        "scan_info": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_alerts": len(filtered_alerts)
        },
        "risk_summary": categories,
        "detailed_alerts": filtered_alerts,
        "statistics": {},
        "categories": {}
    }

    cat_map = {}
    for a in filtered_alerts:
        risk = a.get('risk', 'Informational')
        
        # Inisialisasi dictionary jika belum ada
        if risk not in cat_map:
            cat_map[risk] = {'alerts': []}  # Bungkus dalam dict
            
        # Append ke key 'alerts'
        cat_map[risk]['alerts'].append(a)

    result['categories'] = cat_map
    return result


def cleanup():
    global page
    try:
        if page:
            page.quit()
    except:
        pass


# ================================
# ========== MAIN SCAN ===========
# ================================

def execute_zap_scan(target_url, max_depth=2, selenium_only=False, traditional_only=False):
    visited = set()
    forms = []
    scan_result = None

    try:
        if not start_zap_daemon():
            return {"scan_info": {"error": True, "error_message": "Failed to start ZAP"}}

        zap = get_zap_client()
        log_msg("[+] Resetting session ZAP...")

        try:
            zap.core.new_session(name="temp_session", overwrite=True)
            time.sleep(2)
        except Exception as e:
            log_msg(f"[!] Warning session reset: {e}")

        if not traditional_only:
            if setup_drission_with_zap():
                visited, forms = drission_crawl_and_interact(target_url, max_depth)
                drission_form_interaction(forms)

        if not selenium_only:
            traditional_zap_scanning(target_url)

        scan_result = get_comprehensive_alerts(target_url)
        if scan_result:
            scan_result["scan_info"]["target_url"] = target_url
            scan_result["scan_info"]["scan_type"] = "passive_only"
            scan_result["statistics"]["urls_tested"] = len(visited)
            scan_result["statistics"]["forms_found"] = len(forms)

    except Exception as e:
        scan_result = {"scan_info": {"error": True, "error_message": str(e)}}
        log_msg(f"[-] Error selama eksekusi: {e}")

    finally:
        cleanup()

    return scan_result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--traditional-only", action="store_true")
    parser.add_argument("--selenium-only", action="store_true")
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--output-json")
    parser.add_argument("--webhook-url")
    parser.add_argument("--json-only", action="store_true")

    args = parser.parse_args()

    target = args.target if args.target.startswith("http") else f"http://{args.target}"

    if not args.json_only:
        log_msg(f"Target: {target}")

    result = execute_zap_scan(
        target,
        max_depth=args.max_depth,
        selenium_only=args.selenium_only,
        traditional_only=args.traditional_only
    )

    if result:
        if args.json_only:
            print(json.dumps(result, indent=2))
        elif args.output_json:
            save_results_to_json(result, args.output_json)

        if args.webhook_url:
            send_results_to_endpoint(result, args.webhook_url)


if __name__ == "__main__":
    main()
