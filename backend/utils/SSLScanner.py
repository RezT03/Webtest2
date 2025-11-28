import json
import logging
import subprocess
import shutil
import sys
from urllib.parse import urlparse

# Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SSLScanner")

def run_ssl_scan(target_url):
    """
    Menjalankan SSLyze dengan parameter spesifik dan parsing JSON yang kuat.
    Mengembalikan Dictionary Summary (untuk kompatibilitas dashboard).
    """
    # 1. Bersihkan Target
    clean_target = target_url.replace("https://", "").replace("http://", "").strip()
    if clean_target.endswith("/"): clean_target = clean_target[:-1]
    if clean_target.endswith(":443"): clean_target = clean_target[:-4]

    logger.info(f"Memulai SSL Scan pada: {clean_target}")

    if not shutil.which("sslyze"):
        logger.error("SSLyze tidak ditemukan.")
        return None

    sslyze_cmd = "sslyze"
    if not shutil.which("sslyze"):
        # Jika tidak ada di PATH, coba panggil via modul python
        # Ini lebih aman di Windows
        try:
            subprocess.run([sys.executable, "-m", "sslyze", "--help"], capture_output=True)
            sslyze_cmd = [sys.executable, "-m", "sslyze"] # Gunakan list untuk command
        except:
            logger.error("SSLyze tidak ditemukan. Install dengan 'pip install sslyze'")
            return None
    else:
        sslyze_cmd = ["sslyze"] # Wrap string ke list

    try:
        # 2. Command
        cmd = [
            "sslyze",
            "--json_out=-",
            "--certinfo", 
            "--tlsv1_2", "--tlsv1_3", 
            "--sslv2", "--sslv3", "--tlsv1", "--tlsv1_1",
            "--heartbleed", 
            "--robot", 
            "--openssl_ccs", 
            clean_target
        ]
        
        # Timeout 3 menit
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        
        # 3. Robust Parsing
        try:
            raw_output = proc.stdout
            # Cari karakter '{' pertama (karena kadang ada warning di atasnya)
            json_start = raw_output.find('{')
            if json_start != -1:
                raw_output = raw_output[json_start:]
            
            data = json.loads(raw_output)
        except:
            logger.error("Gagal parse output SSLyze.")
            return None

        if not data.get("server_scan_results"):
            return None

        server_res = data["server_scan_results"][0]
        
        # Support SSLyze v5 (scan_result) dan versi lama (scan_commands_results)
        scan_data = server_res.get("scan_result") or server_res.get("scan_commands_results")
        
        if not scan_data: return None

        # 4. Bangun Summary Dictionary
        summary = {
            "target": clean_target,
            "certificate": {},
            "vulnerabilities": [],
            "weak_ciphers": []
        }

        def get_res(key):
            val = scan_data.get(key)
            if isinstance(val, dict) and "result" in val: return val["result"]
            return val

        # Info Sertifikat
        cert_info = get_res("certificate_info")
        if cert_info:
            try:
                deploy = cert_info["certificate_deployments"][0]
                leaf = deploy["received_certificate_chain"][0]
                
                # Cek Trust
                is_trusted = False
                for path in deploy.get("path_validation_results", []):
                    if path.get("is_certificate_trusted"): is_trusted = True; break

                summary["certificate"] = {
                    "subject": leaf.get("subject", {}).get("rfc4514_string", "Unknown"),
                    "issuer": leaf.get("issuer", {}).get("rfc4514_string", "Unknown"),
                    "valid_from": leaf.get("not_valid_before") or leaf.get("notBefore") or "",
                    "valid_until": leaf.get("not_valid_after") or leaf.get("notAfter") or "",
                    "is_trusted": is_trusted
                }
            except: pass

        # Vulnerabilities
        if get_res("heartbleed") and get_res("heartbleed").get("is_vulnerable_to_heartbleed"):
            summary["vulnerabilities"].append("Heartbleed Detected! (Critical)")

        robot = get_res("robot")
        if robot:
            robot_res = str(robot.get("robot_result"))
            if "VULNERABLE" in robot_res and "NOT_VULNERABLE" not in robot_res:
                summary["vulnerabilities"].append("ROBOT Attack Detected! (High Risk)")

        if get_res("openssl_ccs_injection") and get_res("openssl_ccs_injection").get("is_vulnerable_to_ccs_injection"):
            summary["vulnerabilities"].append("OpenSSL CCS Injection Detected! (High Risk)")

        # Weak Protocols
        def check_bad_proto(key, name):
            res = get_res(key)
            if res and res.get("accepted_cipher_suites"):
                summary["weak_ciphers"].append(f"{name} Enabled (Risk)")

        check_bad_proto("ssl_2_0_cipher_suites", "SSLv2")
        check_bad_proto("ssl_3_0_cipher_suites", "SSLv3")
        check_bad_proto("tls_1_0_cipher_suites", "TLS 1.0")
        check_bad_proto("tls_1_1_cipher_suites", "TLS 1.1")

        return summary

    except Exception as e:
        logger.error(f"SSL Error: {e}")
        return None

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    res = run_ssl_scan(target)
    print(json.dumps(res, indent=2) if res else json.dumps({"error": "Failed"}))