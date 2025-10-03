import subprocess
import logging
import time
import requests
import json
import sys
import os
import argparse
from urllib.parse import urlparse, urljoin
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from zapv2 import ZAPv2
# from zaproxy import ZapClient

# Setup logger (pindahkan ke sini)
logger = logging.getLogger("ZAPScanner")
logger.setLevel(logging.INFO)
if not logger.hasHandlers():
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
    logger.addHandler(handler)

# Konfigurasi ZAP
ZAP_PORT = 8090
ZAP_HOST = "127.0.0.1"
BASE_URL = f"http://{ZAP_HOST}:{ZAP_PORT}"
ZAP_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../ZAP_2.16.1/zap.sh"))
zap_process = None
driver = None

def is_zap_running():
    """Cek apakah ZAP daemon sudah berjalan di host/port yang diinginkan"""
    try:
        resp = requests.get("http://127.0.0.1:8090/JSON/core/view/version/", timeout=3)
        return resp.status_code == 200
    except Exception:
        return False

def start_zap_daemon():
    """Memulai ZAP daemon jika belum berjalan"""
    global zap_process
    if is_zap_running():
        print("[+] ZAP daemon sudah berjalan, tidak perlu memulai ulang.")
        return True

    print("[+] Memulai ZAP daemon...")
    cmd = [
        ZAP_PATH,
        "-daemon",
        "-port", str(ZAP_PORT),
        "-host", ZAP_HOST,
        "-config", "api.disablekey=true"
    ]
    try:
        zap_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        print("[+] Menunggu ZAP daemon siap...")
        wait_for_zap()
        print("[+] ZAP daemon berhasil dimulai")
        return True
    except FileNotFoundError:
        print("[-] Error: Perintah 'zap' tidak ditemukan")
        return False
    except Exception as e:
        print(f"[-] Error memulai ZAP daemon: {e}")
        return False
    # if is_zap_running():
    #     print("[+] ZAP daemon terdeteksi di container.")
    #     return True
    # print("[-] ZAP tidak ditemukan. Pastikan container ZAP berjalan.")
    # return False

def wait_for_zap(timeout=60):
    """Menunggu ZAP daemon siap"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(f"{BASE_URL}/JSON/core/view/version/")
            if response.status_code == 200:
                version_info = response.json()
                print(f"[+] ZAP Version: {version_info.get('version', 'Unknown')}")
                return True
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(2)
    
    raise Exception("Timeout menunggu ZAP daemon siap")

def setup_selenium_with_zap_proxy():
    """Setup Selenium dengan ZAP proxy"""
    global driver
    print("[+] Setting up Selenium dengan ZAP proxy...")
    
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        
        # Configure proxy untuk ZAP
        chrome_options.add_argument(f"--proxy-server=http://{ZAP_HOST}:{ZAP_PORT}")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--ignore-ssl-errors")
        chrome_options.add_argument("--ignore-certificate-errors-spki-list")
        
        # Disable images dan CSS untuk performa (opsional)
        prefs = {
            "profile.managed_default_content_settings.images": 2,
            "profile.default_content_setting_values.notifications": 2
        }
        chrome_options.add_experimental_option("prefs", prefs)
        
        driver = webdriver.Chrome(options=chrome_options)
        driver.set_page_load_timeout(30)
        
        print("[+] Selenium WebDriver siap dengan ZAP proxy")
        return True
        
    except Exception as e:
        print(f"[-] Error setting up Selenium: {e}")
        print("    Pastikan ChromeDriver terinstall: sudo apt install chromium-chromedriver")
        return False

def make_api_request(endpoint, params=None):
    """Membuat request ke ZAP API"""
    if params is None:
        params = {}
    
    try:
        response = requests.get(f"{BASE_URL}{endpoint}", params=params)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"[-] Error API request ke {endpoint}: {e}")
        return None

def selenium_crawl_and_interact(target_url, max_depth=2):
    """Crawl website menggunakan Selenium untuk memicu JS dan AJAX"""
    print(f"\n[+] === SELENIUM CRAWLING + INTERACTION ===")
    print(f"[+] Target: {target_url}")
    
    visited_urls = set()
    urls_to_visit = [target_url]
    forms_found = []
    
    for depth in range(max_depth):
        if not urls_to_visit:
            break
            
        current_urls = urls_to_visit.copy()
        urls_to_visit = []
        
        print(f"[+] Crawling depth {depth + 1}...")
        
        for url in current_urls:
            if url in visited_urls:
                continue
                
            try:
                print(f"[+] Mengunjungi: {url}")
                driver.get(url)
                visited_urls.add(url)
                
                # Tunggu halaman load
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
                
                # Scroll untuk trigger lazy loading
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                time.sleep(2)
                
                # Klik button dan link untuk trigger AJAX
                try:
                    buttons = driver.find_elements(By.TAG_NAME, "button")[:5]  # Limit 5 buttons
                    for btn in buttons:
                        try:
                            if btn.is_displayed() and btn.is_enabled():
                                driver.execute_script("arguments[0].click();", btn)
                                time.sleep(1)
                        except:
                            pass
                except:
                    pass
                
                # Cari forms untuk testing
                try:
                    forms = driver.find_elements(By.TAG_NAME, "form")
                    for form in forms:
                        form_action = form.get_attribute("action") or url
                        form_method = form.get_attribute("method") or "GET"
                        forms_found.append({
                            'url': url,
                            'action': form_action,
                            'method': form_method
                        })
                except:
                    pass
                
                # Cari link baru
                try:
                    links = driver.find_elements(By.TAG_NAME, "a")
                    for link in links[:20]:  # Limit 20 links
                        href = link.get_attribute("href")
                        if href and href.startswith(target_url) and href not in visited_urls:
                            urls_to_visit.append(href)
                except:
                    pass
                
            except TimeoutException:
                print(f"[-] Timeout loading: {url}")
                continue
            except Exception as e:
                print(f"[-] Error accessing {url}: {e}")
                continue
    
    print(f"[+] Selenium crawling selesai:")
    print(f"    - {len(visited_urls)} URLs dikunjungi")
    print(f"    - {len(forms_found)} forms ditemukan")
    
    return visited_urls, forms_found

def selenium_form_interaction(forms_found):
    """Interaksi dengan forms untuk trigger lebih banyak traffic"""
    print(f"\n[+] === FORM INTERACTION ===")
    
    for i, form_info in enumerate(forms_found[:10], 1):
        try:
            print(f"[+] Testing form {i}: {form_info['action']}")
            driver.get(form_info['url'])
            
            # Cari form elements
            forms = driver.find_elements(By.TAG_NAME, "form")
            if not forms:
                continue
                
            form = forms[0]  # Ambil form pertama
            
            # Fill input fields dengan test data
            inputs = form.find_elements(By.TAG_NAME, "input")
            for inp in inputs:
                input_type = inp.get_attribute("type")
                input_name = inp.get_attribute("name")
                
                if input_type in ["text", "email", "search"]:
                    inp.clear()
                    inp.send_keys("test_input")
                elif input_type == "password":
                    inp.clear()
                    inp.send_keys("test_password")
                
            # Submit form (tapi jangan benar-benar submit untuk safety)
            # form.submit()  # Uncomment jika ingin test submit
            
        except Exception as e:
            print(f"[-] Error interacting with form: {e}")
            continue

def traditional_zap_scanning(target_url):
    """Scanning traditional ZAP (spider + passive + active)"""
    print(f"\n[+] === TRADITIONAL ZAP SCANNING ===")
    
    # Spider scan
    print("[+] Spider scanning...")
    endpoint = "/JSON/spider/action/scan/"
    params = {"url": target_url}
    result = make_api_request(endpoint, params)
    
    if result:
        scan_id = result.get('scan')
        while True:
            endpoint = "/JSON/spider/view/status/"
            params = {"scanId": scan_id}
            status = make_api_request(endpoint, params)
            
            if status and status.get('status') == '100':
                print("[+] Spider scan selesai")
                break
            time.sleep(3)
    
    # Passive scan
    print("[+] Passive scanning...")
    endpoint = "/JSON/core/action/accessUrl/"
    params = {"url": target_url}
    make_api_request(endpoint, params)
    
    while True:
        endpoint = "/JSON/pscan/view/recordsToScan/"
        records = make_api_request(endpoint)
        if records and int(records.get('recordsToScan', '0')) == 0:
            print("[+] Passive scan selesai")
            break
        time.sleep(2)

def get_comprehensive_alerts():
    """Mendapatkan hasil alert comprehensive dan return dalam format JSON"""
    print(f"\n[+] === MENGAMBIL HASIL COMPREHENSIVE ===")
    
    endpoint = "/JSON/core/view/alerts/"
    alerts = make_api_request(endpoint)
    
    if not alerts:
        print("[-] Gagal mengambil hasil alert")
        return None
    
    alert_list = alerts.get('alerts', [])
    
    # Kategorisasi alerts
    categories = {
        'XSS': [],
        'SQL Injection': [],
        'CSRF': [],
        'Information Disclosure': [],
        'Security Headers': [],
        'Others': []
    }
    
    risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    
    for alert in alert_list:
        name = alert.get('name', '').lower()
        risk = alert.get('risk', 'Informational')
        
        # Count by risk level
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        # Kategorisasi berdasarkan jenis
        if 'xss' in name or 'cross site scripting' in name:
            categories['XSS'].append(alert)
        elif 'sql' in name or 'injection' in name:
            categories['SQL Injection'].append(alert)
        elif 'csrf' in name or 'cross site request' in name:
            categories['CSRF'].append(alert)
        elif 'disclosure' in name or 'information' in name:
            categories['Information Disclosure'].append(alert)
        elif 'header' in name or 'security' in name:
            categories['Security Headers'].append(alert)
        else:
            categories['Others'].append(alert)
    
    # Build comprehensive JSON result
    scan_result = {
        "scan_info": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target_url": "",  # Will be filled by caller
            "total_alerts": len(alert_list),
            "scan_type": "hybrid"  # Will be updated by caller
        },
        "risk_summary": risk_counts,
        "categories": {},
        "detailed_alerts": alert_list,
        "statistics": {
            "urls_tested": 0,  # Will be filled by caller
            "forms_found": 0   # Will be filled by caller
        }
    }
    
    # Add category summaries
    for category, cat_alerts in categories.items():
        if cat_alerts:
            scan_result["categories"][category] = {
                "count": len(cat_alerts),
                "alerts": cat_alerts
            }
    
    # Print summary to console
    print(f"[+] COMPREHENSIVE SECURITY ASSESSMENT:")
    print("=" * 80)
    
    total_issues = len(alert_list)
    if total_issues == 0:
        print("[+] Tidak ada kerentanan yang ditemukan")
    else:
        print(f"[+] Total Issues: {total_issues}")
        print(f"[+] Risk Distribution:")
        for risk, count in risk_counts.items():
            if count > 0:
                print(f"    - {risk}: {count}")
        
        print(f"\n[+] By Category:")
        for category, cat_alerts in categories.items():
            if cat_alerts:
                print(f"    - {category}: {len(cat_alerts)} issues")
    
    print("=" * 80)
    
    return scan_result

def save_results_to_json(scan_result, filename=None):
    """Simpan hasil scan ke file JSON"""
    if not scan_result:
        print("[-] Tidak ada hasil untuk disimpan")
        return None
    
    if not filename:
        target_domain = urlparse(scan_result["scan_info"]["target_url"]).netloc
        timestamp = int(time.time())
        filename = f"zap_scan_result_{target_domain}_{timestamp}.json"
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(scan_result, f, indent=2, ensure_ascii=False)
        
        print(f"[+] Hasil scan disimpan ke: {filename}")
        print(f"[+] Ukuran file: {os.path.getsize(filename)} bytes")
        return filename
        
    except Exception as e:
        print(f"[-] Error menyimpan file JSON: {e}")
        return None

def send_results_to_endpoint(scan_result, webhook_url=None):
    """Kirim hasil scan ke endpoint/webhook"""
    if not scan_result or not webhook_url:
        return False
    
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(webhook_url, json=scan_result, headers=headers, timeout=30)
        
        if response.status_code == 200:
            print(f"[+] Hasil berhasil dikirim ke: {webhook_url}")
            return True
        else:
            print(f"[-] Gagal mengirim hasil: HTTP {response.status_code}")
            return False
            
    except Exception as e:
        print(f"[-] Error mengirim hasil: {e}")
        return False

def print_json_summary(scan_result):
    """Print ringkasan hasil dalam format yang mudah dibaca"""
    if not scan_result:
        return
    
    print(f"\n[+] === JSON RESULT SUMMARY ===")
    print(f"Timestamp: {scan_result['scan_info']['timestamp']}")
    print(f"Target: {scan_result['scan_info']['target_url']}")
    print(f"Scan Type: {scan_result['scan_info']['scan_type']}")
    print(f"Total Alerts: {scan_result['scan_info']['total_alerts']}")
    print(f"URLs Tested: {scan_result['statistics']['urls_tested']}")
    print(f"Forms Found: {scan_result['statistics']['forms_found']}")
    
    print(f"\nRisk Distribution:")
    for risk, count in scan_result['risk_summary'].items():
        if count > 0:
            print(f"  {risk}: {count}")
    
    print(f"\nCategories Found:")
    for category, data in scan_result['categories'].items():
        print(f"  {category}: {data['count']} issues")
    
    print("=" * 50)

def cleanup():
    """Cleanup resources"""
    global driver, zap_process
    
    print(f"\n[+] Cleaning up...")
    
    if driver:
        try:
            driver.quit()
        except:
            pass
    
    if zap_process:
        try:
            endpoint = "/JSON/core/action/shutdown/"
            make_api_request(endpoint)
            time.sleep(3)
        except:
            pass
        
        if zap_process.poll() is None:
            zap_process.terminate()

def run_zap_scan(target_url):
    logger.info("🛡️ [3] Menjalankan/memastikan ZAP daemon berjalan...")
    zap_ready = start_zap_daemon()
    if zap_ready:
        logger.info("🛡️ Menunggu ZAP daemon siap...")
        wait_for_zap(timeout=90)
        logger.info("🛡️ Menjalankan ZAP scanning...")
        zap = ZAPv2(apikey=None, proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})
        zap_data = run_zap_scan(target_url)
        # ...
def hybrid_zap_scan(target_url, max_depth=2, selenium_only=False, traditional_only=False):
    # 1. Start daemon
    if not start_zap_daemon():
        return {"error": "ZAP daemon gagal dijalankan"}
    # 2. Setup Selenium jika perlu
    if not traditional_only:
        if not setup_selenium_with_zap_proxy():
            traditional_only = True
    visited_urls, forms_found = set(), []
    if not traditional_only:
        visited_urls, forms_found = selenium_crawl_and_interact(target_url, max_depth)
        selenium_form_interaction(forms_found)
    if not selenium_only:
        traditional_zap_scanning(target_url)
    scan_result = get_comprehensive_alerts()
    if scan_result:
        scan_result["scan_info"]["target_url"] = target_url
        scan_result["statistics"]["urls_tested"] = len(visited_urls)
        scan_result["statistics"]["forms_found"] = len(forms_found)
    return scan_result

def main():
    parser = argparse.ArgumentParser(description="ZAP + Selenium Hybrid Scanner")
    parser.add_argument("target", help="Target URL untuk di-scan")
    parser.add_argument("--selenium-only", action="store_true", help="Hanya gunakan Selenium crawling")
    parser.add_argument("--traditional-only", action="store_true", help="Hanya gunakan traditional ZAP")
    parser.add_argument("--max-depth", type=int, default=2, help="Max crawling depth (default: 2)")
    parser.add_argument("--output-json", type=str, help="Nama file JSON untuk menyimpan hasil")
    parser.add_argument("--webhook-url", type=str, help="URL endpoint untuk mengirim hasil JSON")
    parser.add_argument("--json-only", action="store_true", help="Hanya output JSON, minimal console output")

    args = parser.parse_args()

    target_url = args.target
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url

    if not args.json_only:
        print("=" * 80)
        print("     OWASP ZAP + SELENIUM HYBRID SCANNER")
        print("=" * 80)
        print(f"Target URL: {target_url}")
        print(f"Mode: {'Selenium Only' if args.selenium_only else 'Traditional Only' if args.traditional_only else 'Hybrid'}")
        if args.output_json:
            print(f"JSON Output: {args.output_json}")
        if args.webhook_url:
            print(f"Webhook URL: {args.webhook_url}")
        print("=" * 80)
    
    # Variables untuk tracking
    visited_urls = set()
    forms_found = []
    scan_result = None
    
    try:
        # 1. Start ZAP daemon
        if not start_zap_daemon():
            sys.exit(1)
        
        # 2. Setup Selenium
        if not args.traditional_only:
            if not setup_selenium_with_zap_proxy():
                if not args.json_only:
                    print("[!] Fallback ke traditional scanning...")
                args.traditional_only = True
        
        # 3. Selenium crawling + interaction
        if not args.traditional_only:
            visited_urls, forms_found = selenium_crawl_and_interact(target_url, args.max_depth)
            selenium_form_interaction(forms_found)
        
        # 4. Traditional ZAP scanning
        if not args.selenium_only:
            traditional_zap_scanning(target_url)
        
        # 5. Get comprehensive results in JSON format
        scan_result = get_comprehensive_alerts()

        if scan_result:
            # Update scan info
            scan_result["scan_info"]["target_url"] = target_url
            scan_result["scan_info"]["scan_type"] = "selenium_only" if args.selenium_only else "traditional_only" if args.traditional_only else "hybrid"
            scan_result["statistics"]["urls_tested"] = len(visited_urls)
            scan_result["statistics"]["forms_found"] = len(forms_found)

            # Output handling
            print(json.dumps(scan_result, indent=2, ensure_ascii=False))
            if args.output_json:
                save_results_to_json(scan_result, args.output_json)
            if args.webhook_url:
                send_results_to_endpoint(scan_result, args.webhook_url)

    except KeyboardInterrupt:
        if scan_result:
            scan_result["scan_info"]["status"] = "interrupted"
            print(json.dumps(scan_result, indent=2, ensure_ascii=False))
    except Exception as e:
        error_result = {
            "scan_info": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "target_url": target_url,
                "status": "error",
                "error_message": str(e)
            }
        }
        print(json.dumps(error_result, indent=2, ensure_ascii=False))
    finally:
        cleanup()

if __name__ == "__main__":
    main()