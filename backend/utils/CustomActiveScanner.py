import requests
import re
import concurrent.futures
import logging
import time
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse
from bs4 import BeautifulSoup

# Logger
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [ACTIVE] %(message)s')
logger = logging.getLogger("CustomScanner")

class CustomActiveScanner:
    def __init__(self, target_url, cookie=None):
        self.target_url = target_url
        self.session = requests.Session()
        if cookie:
            self.session.headers.update({'Cookie': cookie})
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Compatible; ThesisScanner/1.0; +https://github.com/yourrepo)',
            'Content-Type': 'application/x-www-form-urlencoded' 
        })
        
        # PAYLOADS (Ditingkatkan)
        self.payloads = {
            "SQLi_Error": ["'", '"', "' OR '1'='1", "admin' --"],
            "XSS_Reflected": ["<script>alert('XSS')</script>", "\"><img src=x onerror=alert(1)>"],
            # Novelty: Payload untuk Blind SQLi (Time Based)
            "SQLi_Blind": ["' AND SLEEP(5)--+", "1 AND SLEEP(5)", "'; WAITFOR DELAY '0:0:5'--"],
            "LFI": ["../../../../etc/passwd", "C:\\Windows\\win.ini"]
        }

    def _extract_inputs(self, url):
        """Ekstrak parameter URL dan Form"""
        injection_points = []
        try:
            res = self.session.get(url, timeout=5)
            # 1. URL Parameters
            parsed = urlparse(url)
            if parsed.query:
                params = dict(parse_qsl(parsed.query))
                for k, v in params.items():
                    injection_points.append({
                        "type": "url_param", "method": "GET", "url": url,
                        "param_name": k, "original_value": v, "params": params
                    })
            # 2. Form Inputs (Simple extraction)
            soup = BeautifulSoup(res.text, 'html.parser')
            for form in soup.find_all('form'):
                action = urljoin(url, form.get('action'))
                method = form.get('method', 'get').upper()
                inputs = {i.get('name'): 'test' for i in form.find_all('input') if i.get('name')}
                for k, v in inputs.items():
                    injection_points.append({
                        "type": "form", "method": method, "url": action,
                        "param_name": k, "original_value": v, "form_data": inputs
                    })
        except: pass
        return injection_points

    def _test_idor(self):
        """
        NOVELTY FEATURE: Broken Access Control (IDOR) Detection
        Mencoba memanipulasi ID numerik di URL.
        Contoh: /user/100 -> Coba akses /user/99 atau /user/101
        """
        alerts = []
        try:
            # Cari pola ID numerik di URL (misal: ?id=50 atau /user/50)
            parsed = urlparse(self.target_url)
            # Regex untuk mencari angka di query param atau path
            id_pattern = re.compile(r'([?&][a-zA-Z0-9_]+=|/)(\d+)')
            
            matches = id_pattern.findall(self.target_url)
            if not matches:
                return []

            logger.info("[IDOR] Mendeteksi potensi ID di URL, mencoba manipulasi...")
            
            original_res = self.session.get(self.target_url, timeout=5)
            original_len = len(original_res.text)
            
            # Manipulasi: Kurangi ID dengan 1
            modified_url = id_pattern.sub(lambda m: f"{m.group(1)}{int(m.group(2))-1}", self.target_url)
            
            test_res = self.session.get(modified_url, timeout=5)
            test_len = len(test_res.text)

            # Logika Deteksi Sederhana:
            # Jika status 200 OK DAN panjang konten berbeda signifikan DAN tidak ada error page
            if test_res.status_code == 200 and abs(original_len - test_len) > 50:
                # Validasi tambahan: pastikan bukan halaman login
                if "login" not in test_res.url and "signin" not in test_res.url:
                    alerts.append({
                        "alert": "Potential IDOR / Broken Access Control",
                        "risk": "High",
                        "description": f"URL merespons berbeda saat ID dimanipulasi.\nOriginal: {self.target_url}\nModified: {modified_url}\nIndikasi akses data milik user lain.",
                        "solution": "Implementasikan validasi kepemilikan data pada sisi server (Authorize ownership).",
                        "url": self.target_url
                    })
        except Exception as e:
            logger.error(f"IDOR Check Error: {e}")
            
        return alerts

    def _test_payload(self, point, attack_type, payload):
        try:
            # Siapkan data
            data = point.get('form_data', {}).copy() if point['type'] == 'form' else point.get('params', {}).copy()
            data[point['param_name']] = payload
            
            start_time = time.time()
            if point['method'] == 'POST':
                r = self.session.post(point['url'], data=data, timeout=10)
            else:
                r = self.session.get(point['url'], params=data, timeout=10)
            
            elapsed = time.time() - start_time
            resp_text = r.text.lower()

            # --- LOGIKA DETEKSI ---
            if attack_type == "SQLi_Error":
                if "syntax error" in resp_text or "mysql" in resp_text:
                    return f"SQL Error detected (Payload: {payload})"
            
            elif attack_type == "SQLi_Blind":
                # NOVELTY: Time-Based Detection
                # Jika payload sleep(5) membuat request > 4.5 detik, kemungkinan vuln
                if elapsed > 4.5:
                    return f"Time-Based SQLi detected (Delay: {elapsed:.2f}s)"

            elif attack_type == "XSS_Reflected":
                if payload in r.text:
                    return f"Reflected XSS detected (Payload: {payload})"
                    
        except: pass
        return None

    def run(self):
        logger.info(f"Memulai Custom Active Scan pada {self.target_url}")
        all_alerts = []
        
        # 1. Cek IDOR (Fitur Baru)
        all_alerts.extend(self._test_idor())
        
        # 2. Fuzzing Injeksi
        points = self._extract_inputs(self.target_url)
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_map = {}
            for point in points:
                for atype, payloads in self.payloads.items():
                    for p in payloads:
                        future = executor.submit(self._test_payload, point, atype, p)
                        future_map[future] = (atype, p)
            
            for future in concurrent.futures.as_completed(future_map):
                res = future.result()
                if res:
                    atype, _ = future_map[future]
                    all_alerts.append({
                        "alert": atype.split('_')[0], # SQLi_Blind -> SQLi
                        "risk": "High",
                        "description": res,
                        "solution": "Sanitasi input dan gunakan Prepared Statements.",
                        "url": self.target_url
                    })
                    break # Stop fuzzing if found one vuln per param (Optimization)

        return all_alerts

def run_custom_scan(target_url, cookie=None):
    return CustomActiveScanner(target_url, cookie).run()