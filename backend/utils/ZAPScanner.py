# zapScanner.py — Integrasi penuh dengan dashboard dan database
from zapv2 import ZAPv2
import time
import logging
import os
import mysql.connector
from dotenv import load_dotenv
from pathlib import Path

# Load .env
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / '.env')

# Koneksi DB
DB_CONFIG = {
    'host': os.getenv("DB_HOST", "localhost"),
    'user': os.getenv("DB_USER", "root"),
    'password': os.getenv("DB_PASS", ""),
    'database': os.getenv("DB_NAME", "websec")
}

# Konfigurasi ZAP
ZAP_ADDRESS = 'localhost'
ZAP_PORT = '8090'
ZAP_API_KEY = '12345'
ZAP_BASE = f'http://{ZAP_ADDRESS}:{ZAP_PORT}'

zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': ZAP_BASE, 'https': ZAP_BASE})

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s: %(message)s')

def save_zap_results(target_url, hasil):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        for item in hasil:
            cursor.execute("""
                INSERT INTO zap_results (url, risk, alert, description, solution, param)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                target_url,
                item.get("risk"),
                item.get("alert"),
                item.get("desc"),
                item.get("solution"),
                item.get("param")
            ))
        conn.commit()
        conn.close()
        logging.info("✅ Hasil ZAP disimpan ke database")
    except Exception as e:
        logging.error(f"❌ Gagal simpan ZAP ke database: {e}")

def run_zap_scan(target_url):
    logging.info(f"▶️ Memulai ZAP Scan untuk {target_url}")

    zap.urlopen(target_url)
    time.sleep(2)

    scanid = zap.spider.scan(target_url)
    while int(zap.spider.status(scanid)) < 100:
        logging.debug(f"[Spider] Progress: {zap.spider.status(scanid)}%")
        time.sleep(2)

    logging.info("✅ Spider selesai, memulai Active Scan")

    ascanid = zap.ascan.scan(target_url)
    while int(zap.ascan.status(ascanid)) < 100:
        logging.debug(f"[Active Scan] Progress: {zap.ascan.status(ascanid)}%")
        time.sleep(5)

    logging.info("✅ Active Scan selesai, mengambil hasil")
    alerts = zap.core.alerts(baseurl=target_url)

    hasil = []
    for alert in alerts:
        hasil.append({
            "risk": alert.get("risk"),
            "alert": alert.get("alert"),
            "desc": alert.get("desc"),
            "solution": alert.get("solution"),
            "url": alert.get("url"),
            "param": alert.get("param")
        })

    logging.info(f"📦 Jumlah alert ditemukan oleh ZAP: {len(hasil)}")
    save_zap_results(target_url, hasil)
    return hasil

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("❌ Gunakan: python zapScanner.py <target_url>")
        exit()
    target = sys.argv[1]
    hasil = run_zap_scan(target)
    for h in hasil:
        print(f"[{h['risk']}] {h['alert']}: {h['desc']}\nSolusi: {h['solution']}\nURL: {h['url']}\nParam: {h['param']}\n")
