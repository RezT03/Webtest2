import time
import logging
import os
import subprocess
import socket
import json
from zapv2 import ZAPv2
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions

ZAP_API_KEY = os.getenv("ZAP_API_KEY", "") or '1234'
ZAP_ADDRESS = "127.0.0.1"
ZAP_PORT = "8080"
ZAP_PATH = "zap"  # ganti jika zap.sh kamu beda
ZAP = ZAPv2(apikey=ZAP_API_KEY, proxies={
    'http': f'http://{ZAP_ADDRESS}:{ZAP_PORT}',
    'https': f'http://{ZAP_ADDRESS}:{ZAP_PORT}'
})


logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

def start_zap_daemon():
    try:
        ZAP.core.version
        logging.info("✅ ZAP sudah aktif.")
    except Exception:
        logging.info("🚀 Memulai ZAP daemon...")
        subprocess.Popen([
            ZAP_PATH,
            "-daemon",
            f"-port", ZAP_PORT,
            "-config", "api.disablekey=true"
        ])
        wait_zap_ready()


def wait_zap_ready(timeout=60):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((ZAP_ADDRESS, int(ZAP_PORT)), timeout=2):
                # Cek API ZAP benar-benar ready
                try:
                    version = ZAP.core.version
                    logging.info(f"✅ ZAP daemon siap (versi: {version})")
                    return
                except Exception:
                    time.sleep(2)
        except Exception:
            time.sleep(2)
    raise RuntimeError("❌ ZAP tidak dapat dijangkau di port 8080 setelah 60 detik")
 
def selenium_crawl_and_interact(target_url):
    logging.info(f"🔍 Selenium browsing target: {target_url}")
    options = ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    options.add_argument(f'--proxy-server=http://{ZAP_ADDRESS}:{ZAP_PORT}')
    driver = webdriver.Chrome(options=options)
    driver.get(target_url)
    time.sleep(5)
    page_source = driver.page_source
    driver.quit()
    return page_source

def traditional_zap_scanning(target_url):
    
    logging.info("🚀 Menjalankan ZAP spider...")
    scan_id = ZAP.spider.scan(target_url)
    time.sleep(2)
    while int(ZAP.spider.status(scan_id)) < 100:
        logging.info(f"Spider progress: {ZAP.spider.status(scan_id)}%")
        time.sleep(2)
    logging.info("✅ Spider selesai")

    logging.info("🚀 Menjalankan Active Scan...")
    ascan_id = ZAP.ascan.scan(target_url)
    while int(ZAP.ascan.status(ascan_id)) < 100:
        logging.info(f"Active scan progress: {ZAP.ascan.status(ascan_id)}%")
        time.sleep(5)
    logging.info("✅ Active scan selesai")

def get_comprehensive_alerts():
    alerts = ZAP.core.alerts()
    hasil = []
    for a in alerts:
        hasil.append({
            'alert': a.get('alert'),
            'risk': a.get('risk'),
            'url': a.get('url'),
            'desc': a.get('description', '')[:200],
            'solution': a.get('solution', ''),
            'cweid': a.get('cweid'),
            'param': a.get('param', '-')
        })
    return hasil

def cleanup():
    try:
        ZAP.core.shutdown()
    except:
        pass

def run_zap_scan(target_url):
    start_zap_daemon()
    ZAP.ascan.set_option_thread_per_host(10)
    selenium_crawl_and_interact(target_url)
    traditional_zap_scanning(target_url)
    hasil = get_comprehensive_alerts()
    return hasil

if __name__ == '__main__':
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    try:
        hasil = run_zap_scan(target)
        output_json = json.dumps({"zap_alerts": hasil})
        print(output_json)
        if not output_json or not output_json.strip().startswith("{"):
            logging.error("Output Python tidak valid:", output_json)
            sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
