import json
import logging
import subprocess
import shutil
import sys
import os

# Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SSLScanner")

def run_ssl_scan(target_url):
    """
    Menjalankan SSLyze dengan parameter spesifik dan parsing JSON yang kuat.
    Mengembalikan Dictionary Summary.
    """
    # 1. Bersihkan Target
    # Menghapus skema (http/https) dan path agar hanya menyisakan domain/hostname
    clean_target = target_url.replace("https://", "").replace("http://", "").split('/')[0].strip()
    if ":" in clean_target:
        clean_target = clean_target.split(":")[0]

    logger.info(f"Memulai SSL Scan pada: {clean_target}")

    # 2. Tentukan Perintah SSLyze (Detect PATH vs Module)
    sslyze_cmd = []
    if shutil.which("sslyze"):
        sslyze_cmd = ["sslyze"]
    else:
        try:
            # Coba jalankan sebagai modul python
            subprocess.run([sys.executable, "-m", "sslyze", "--help"], 
                           capture_output=True, check=True, timeout=10)
            sslyze_cmd = [sys.executable, "-m", "sslyze"]
        except Exception:
            logger.error("SSLyze tidak ditemukan di PATH maupun modul Python. Install dengan 'pip install sslyze'")
            return {"error": "SSLyze not installed"}

    try:
        # 3. Bangun List Argumen
        cmd = sslyze_cmd + [
            "--json_out=-",
            "--certinfo", 
            "--tlsv1_2", "--tlsv1_3", 
            "--sslv2", "--sslv3", "--tlsv1", "--tlsv1_1",
            "--heartbleed", 
            "--robot", 
            "--openssl_ccs", 
            clean_target
        ]
        
        # Eksekusi dengan timeout 3 menit
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        
        # Log jika ada error di stderr sslyze tapi proses tetap berjalan
        if proc.stderr:
            logger.warning(f"SSLyze Warning/Error: {proc.stderr[:100]}...")

        # 4. Parsing JSON
        raw_output = proc.stdout
        json_start = raw_output.find('{')
        if json_start == -1:
            logger.error("Output SSLyze tidak valid (JSON tidak ditemukan).")
            return {"error": "Invalid SSLyze output format"}
        
        data = json.loads(raw_output[json_start:])

        if not data.get("server_scan_results"):
            logger.error("Scan results kosong.")
            return {"error": "No scan results from server"}

        server_res = data["server_scan_results"][0]
        
        # Support v5 (scan_result) dan versi lama
        scan_data = server_res.get("scan_result") or server_res.get("scan_commands_results")
        if not scan_data: 
            return {"error": "Missing scan_result data structure"}

        # 5. Bangun Summary Dictionary
        summary = {
            "target": clean_target,
            "certificate": {"is_trusted": False},
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
                    if path.get("is_certificate_trusted"): 
                        is_trusted = True
                        break

                summary["certificate"] = {
                    "subject": leaf.get("subject", {}).get("rfc4514_string", "Unknown"),
                    "issuer": leaf.get("issuer", {}).get("rfc4514_string", "Unknown"),
                    "valid_from": leaf.get("not_valid_before") or leaf.get("notBefore") or "",
                    "valid_until": leaf.get("not_valid_after") or leaf.get("notAfter") or "",
                    "is_trusted": is_trusted
                }
            except Exception as e:
                logger.warning(f"Gagal parsing cert details: {e}")

        # Vulnerabilities
        hb = get_res("heartbleed")
        if hb and hb.get("is_vulnerable_to_heartbleed"):
            summary["vulnerabilities"].append("Heartbleed Detected! (Critical)")

        robot = get_res("robot")
        if robot:
            robot_res = str(robot.get("robot_result"))
            if "VULNERABLE" in robot_res and "NOT_VULNERABLE" not in robot_res:
                summary["vulnerabilities"].append("ROBOT Attack Detected! (High Risk)")

        ccs = get_res("openssl_ccs_injection")
        if ccs and ccs.get("is_vulnerable_to_ccs_injection"):
            summary["vulnerabilities"].append("OpenSSL CCS Injection Detected! (High Risk)")

        # Weak Protocols
        bad_protos = [
            ("ssl_2_0_cipher_suites", "SSLv2"),
            ("ssl_3_0_cipher_suites", "SSLv3"),
            ("tls_1_0_cipher_suites", "TLS 1.0"),
            ("tls_1_1_cipher_suites", "TLS 1.1"),
        ]
        
        for key, name in bad_protos:
            res = get_res(key)
            if res and res.get("accepted_cipher_suites"):
                summary["weak_ciphers"].append(f"{name} Enabled (Risk)")

        return summary

    except subprocess.TimeoutExpired:
        logger.error("Scan timeout (3 menit).")
        return {"error": "Scan timed out"}
    except Exception as e:
        logger.error(f"SSL Scan Error: {e}")
        return {"error": str(e)}

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    res = run_ssl_scan(target)
    print(json.dumps(res, indent=2))