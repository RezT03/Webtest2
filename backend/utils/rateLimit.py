import requests
import concurrent.futures
import time
import logging
import sys
import subprocess
import random

# Setup Logger
logger = logging.getLogger("RateLimitTester")
logger.setLevel(logging.INFO)
if not logger.hasHandlers():
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[%(asctime)s] [RATELIMIT] %(message)s'))
    logger.addHandler(handler)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/119.0"
]

def diagnose_with_curl(url):
    """Diagnosa cepat untuk membedakan Down vs Blocked"""
    try:
        cmd = ["curl", "-I", "-L", "--connect-timeout", "5", "-v", url]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stderr = result.stderr.lower()
        stdout = result.stdout.lower()
        
        if "connection reset" in stderr or "recv failure" in stderr or result.returncode == 56:
            return "BLOCKED_RST"
        if "http/1.1 403" in stdout or "http/2 403" in stdout:
            return "BLOCKED_403"
        if "http/1.1 200" in stdout or "http/2 200" in stdout or "location:" in stdout:
            return "ALIVE"
        return "UNKNOWN"
    except: return "ERROR"

def run_rate_limit_test(target_url, level=1):
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    # Config: Level 1 (Quick), 2 (Load), 3 (Stress)
    config = {
        1: {"count": 50, "workers": 10, "desc": "Ringan"},
        2: {"count": 250, "workers": 25, "desc": "Sedang"},
        3: {"count": 1000, "workers": 50, "desc": "Berat"}
    }
    
    try: level = int(level)
    except: level = 1
    if level not in config: level = 1

    cfg = config[level]
    logger.info(f"Test Level {level} ({cfg['count']} reqs) on {target_url}")
    
    # 1. CEK WAF SIGNATURE
    is_waf_detected = False
    waf_name = ""
    try:
        initial_req = requests.head(target_url, timeout=5)
        server_header = initial_req.headers.get("Server", "").lower()
        if "cloudflare" in server_header:
            is_waf_detected = True; waf_name = "Cloudflare"
        elif "akamai" in server_header:
            is_waf_detected = True; waf_name = "Akamai"
        elif "nginx" in server_header:
            pass # Nginx umum, belum tentu WAF
    except: pass

    stats = {"total": 0, "success": 0, "blocked": 0, "error": 0, "codes": {}}

    def send_req(_):
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            r = requests.get(target_url, headers=headers, timeout=5)
            return r.status_code
        except requests.exceptions.ConnectionError: return -1 
        except requests.exceptions.Timeout: return -2 
        except: return 0

    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=cfg["workers"]) as executor:
        futures = [executor.submit(send_req, i) for i in range(cfg["count"])]
        for future in concurrent.futures.as_completed(futures):
            code = future.result()
            stats["total"] += 1
            
            # --- LOGIKA PENILAIAN KETAT ---
            if code in [429, 403]: 
                # Hanya 429 dan 403 yang dihitung sebagai BLOCKED (Aman)
                stats["blocked"] += 1
            elif code < 0 or code >= 500 or code == 0: 
                # Koneksi putus/timeout/error server = ERROR (Bisa jadi Down)
                stats["error"] += 1
            else: 
                # 200, 201, 301, 302, 400, 401, 404, 415, dll.
                # Semua ini dihitung SUCCESS (Request tembus ke aplikasi)
                # Artinya Rate Limit GAGAL memblokir traffic ini.
                stats["success"] += 1
            
            c_str = str(code) if code > 0 else ("Reset" if code == -1 else "Timeout")
            stats["codes"][c_str] = stats["codes"].get(c_str, 0) + 1

    duration = time.time() - start_time
    
    # --- ANALISIS ---
    # Jika > 0 request diblokir dengan kode yang sah, kita anggap ada proteksi
    is_protected_strict = stats["blocked"] > 0
    error_rate = stats["error"] / cfg["count"]
    
    summary = f"Dikirim {cfg['count']} request dalam {duration:.2f}s. "
    
    if is_protected_strict:
        summary += f"<strong>AMAN</strong>: Server/WAF aktif memblokir {stats['blocked']} request dengan kode HTTP {', '.join([k for k in stats['codes'] if k in ['429','403']])}."
        if stats['success'] > 0:
            summary += f" (Namun {stats['success']} request lainnya masih tembus)."
            
    elif error_rate > 0.4:
        # Banyak error/timeout
        if is_waf_detected:
            summary += f"<strong>AMAN (MITIGASI)</strong>: Request gagal/timeout ({stats['error']}) dengan WAF {waf_name} terdeteksi. Kemungkinan Silent Drop."
        else:
            diag = diagnose_with_curl(target_url)
            if diag == "BLOCKED_RST":
                summary += f"<strong>AMAN (FIREWALL)</strong>: Koneksi diputus paksa (Connection Reset)."
            else:
                summary += f"<strong>BERISIKO</strong>: Server overload/timeout ({stats['error']} kegagalan). Tidak ada WAF terdeteksi."

    else:
        # Tidak ada yang diblokir (429/403) dan error rate rendah
        # Ini berarti mayoritas request mendapat respons aplikasi (200, 404, 415, dll)
        summary += f"<strong>RENTAN</strong>: Server menerima dan memproses {stats['success']} request tanpa hambatan. "
        summary += "Tidak ada tanda Rate Limiting (429/403)."

    logger.info(f"Selesai. Blocked: {stats['blocked']}, Passed: {stats['success']}, Errors: {stats['error']}")
    return {"summary": summary, "details": stats, "duration": duration, "level_used": level}

if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    print(json.dumps(run_rate_limit_test(target), indent=2))