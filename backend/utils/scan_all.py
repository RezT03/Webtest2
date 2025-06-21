import os
import subprocess
import logging
import sys
import json
import datetime
from techDetector import detect_software, search_cves_combined
from ZAPScanner import start_zap_daemon, run_zap_scan
from dosTester import estimate_payload_size, run_dos_attack
from formDetector import extract_form_parameters
from pdfExport import export_to_pdf

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def main_scan(url, dos_params=None):
    hasil = {}
    logging.info("Memulai pengujian terhadap: %s", url)

    tech = detect_software(url)
    hasil["tech"] = tech
    logging.info("✅ Deteksi software selesai.")

    cves = search_cves_combined(tech)
    hasil["cves"] = cves
    logging.info("✅ Pencarian CVE selesai.")

    zap = run_zap_scan(url)
    hasil["zap_alerts"] = zap
    logging.info("✅ ZAP Scan selesai.")

    if dos_params:
        dos_summary = run_dos_attack(url, **dos_params)
        hasil["dos_summary"] = dos_summary
        logging.info("✅ DoS selesai.")
    else:
        hasil["dos_summary"] = "Pengujian DoS tidak dijalankan."

    json.dump(hasil, sys.stdout)

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="URL target")
    parser.add_argument("--requests_num", type=int, default=0)
    parser.add_argument("--duration", type=int, default=0)
    parser.add_argument("--packet_size", type=int, default=0)
    parser.add_argument("--dos_enabled", action="store_true")
    args = parser.parse_args()

    dos_args = None
    if args.dos_enabled:
        dos_args = {
            "requests_num": args.requests_num,
            "duration": args.duration,
            "packet_size": args.packet_size
        }

    main_scan(args.url, dos_args)
