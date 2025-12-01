import requests
import concurrent.futures
import time
import logging
import sys
import subprocess
import random
from urllib.parse import urlparse

# Setup Logger
logger = logging.getLogger("RateLimitTester")
logger.setLevel(logging.INFO)
if not logger.hasHandlers():
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[%(asctime)s] [RATELIMIT] %(message)s'))
    logger.addHandler(handler)

# List User Agent untuk rotasi
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/119.0"
]

def diagnose_with_curl(url):
    """
    Diagnosa lanjutan menggunakan cURL untuk membedakan Server Down vs IP Blocked.
    """
    try:
        # -I: Header only, -L: Follow redirect, -v: Verbose, timeout 5s
        cmd = ["curl", "-I", "-L", "--connect-timeout", "5", "-v", url]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        stderr = result.stderr.lower()
        stdout = result.stdout.lower()
        
        # Cek tanda blokir keras (Level Network/Firewall)
        if "connection reset" in stderr or "recv failure" in stderr or result.returncode == 56:
            return "BLOCKED_RST"
        
        # Cek blokir halus (Level Aplikasi/WAF)
        if "http/1.1 403" in stdout or "http/2 403" in stdout:
            return "BLOCKED_403"
        
        # Cek jika server hidup normal
        if "http/1.1 200" in stdout or "http/2 200" in stdout or "location:" in stdout:
            return "ALIVE"
            
        return "UNKNOWN"
    except: return "ERROR"

def run_rate_limit_test(target_url, level=1):
    # Normalisasi URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url 

    # Konfigurasi Beban (Level 1, 2, 3)
    config = {
        1: {"count": 50, "workers": 10, "desc": "Ringan"},
        2: {"count": 250, "workers": 25, "desc": "Sedang"},
        3: {"count": 1000, "workers": 50, "desc": "Berat"}
    }
    
    # Pastikan level valid
    try: level = int(level)
    except: level = 1
    if level not in config: level = 1

    cfg = config[level]
    logger.info(f"Test Level {level} ({cfg['count']} reqs) on {target_url}")
    
    # --- 1. DETEKSI WAF DULU ---
    is_waf_detected = False
    waf_name = "Unknown"
    try:
        initial_req = requests.head(target_url, timeout=5, headers={'User-Agent': random.choice(USER_AGENTS)})
        server_header = initial_req.headers.get("Server", "").lower()
        if "cloudflare" in server_header:
            is_waf_detected = True
            waf_name = "Cloudflare"
        elif "akamai" in server_header:
            is_waf_detected = True
            waf_name = "Akamai"
        elif "imperva" in server_header or "incapsula" in server_header:
            is_waf_detected = True
            waf_name = "Imperva"
    except: pass

    # Statistik
    stats = {"total": 0, "success": 0, "blocked": 0, "error": 0, "codes": {}}

    def send_req(_):
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            # Timeout 5 detik. Jika lebih, dianggap server overload/lambat
            r = requests.get(target_url, headers=headers, timeout=5)
            return r.status_code
        except requests.exceptions.ConnectionError: return -1 # Reset/Refused
        except requests.exceptions.Timeout: return -2 # Timeout
        except: return 0

    start_time = time.time()

    # Eksekusi Paralel
    with concurrent.futures.ThreadPoolExecutor(max_workers=cfg["workers"]) as executor:
        futures = [executor.submit(send_req, i) for i in range(cfg["count"])]
        for future in concurrent.futures.as_completed(futures):
            code = future.result()
            stats["total"] += 1
            
            if code == 200: stats["success"] += 1
            elif code in [429, 403]: stats["blocked"] += 1
            elif code < 0 or code >= 500: stats["error"] += 1 # Error/Timeout
            else: pass # Redirect 3xx dihitung sukses konek
            
            # Labeling kode untuk laporan
            if code == -1: c_str = "Reset"
            elif code == -2: c_str = "Timeout"
            else: c_str = str(code)
            
            stats["codes"][c_str] = stats["codes"].get(c_str, 0) + 1

    duration = time.time() - start_time
    
    # --- ANALISIS CERDAS ---
    is_explicitly_blocked = stats["blocked"] > 0
    error_rate = stats["error"] / cfg["count"]
    reset_count = stats["codes"].get("Reset", 0)
    
    summary = f"Dikirim {cfg['count']} request dalam {duration:.2f}s. "
    
    # KASUS 1: Diblokir Eksplisit (Ideal)
    if is_explicitly_blocked:
        summary += f"**AMAN:** Server/WAF memblokir {stats['blocked']} request (HTTP 429/403)."
    
    # KASUS 2: Diblokir Kasar (Connection Reset)
    elif reset_count > (cfg["count"] * 0.5):
        summary += f"**AMAN (FIREWALL):** {reset_count} koneksi diputus paksa (TCP Reset). Server menolak koneksi secara instan."

    # KASUS 3: Banyak Error/Timeout (Ambigu)
    elif error_rate > 0.4: 
        if is_waf_detected:
            summary += f"**AMAN (MITIGATED):** Mayoritas request gagal/timeout ({stats['error']}) dan WAF {waf_name} terdeteksi.\n"
            summary += "   *Analisis: WAF kemungkinan melakukan 'Silent Drop' atau 'Tarpitting' (memperlambat koneksi) terhadap serangan.*"
        else:
            # Cek diagnosa lanjutan dengan CURL
            diag = diagnose_with_curl(target_url)
            if diag == "BLOCKED_RST" or diag == "BLOCKED_403":
                summary += f"**AMAN (PROTECTED):** Diagnosa mengonfirmasi IP diblokir oleh Firewall/IPS."
            elif diag == "ALIVE":
                summary += f"**BERISIKO:** Server mengalami overload/lambat, tapi tidak memblokir IP secara aktif."
            else:
                summary += f"**RENTAN:** Server down/crash ({stats['error']} kegagalan)."

    # KASUS 4: Semua Tembus (Rentan)
    else:
        if is_waf_detected:
             summary += f"**WASPADA:** Menggunakan {waf_name}, namun {stats['success']} request lolos. Cek konfigurasi Rate Limit WAF."
        else:
             summary += f"**RENTAN:** Server menerima {stats['success']} request tanpa hambatan."

    logger.info(f"Selesai. Summary: {summary}")
    return {"summary": summary, "details": stats, "duration": duration, "level_used": level}

if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    # Ambil level dari argumen ke-2 jika ada
    lvl = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    print(json.dumps(run_rate_limit_test(target, level=lvl), indent=2))