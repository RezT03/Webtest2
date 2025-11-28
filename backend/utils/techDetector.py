import re
import requests
import os
import logging
from pathlib import Path
from dotenv import load_dotenv
import time
import sys
import json
from datetime import datetime, timedelta
from packaging import version

# --- DRISSIONPAGE IMPORT ---
try:
    from DrissionPage import ChromiumPage, ChromiumOptions
except ImportError:
    sys.stderr.write("[-] DrissionPage not found. Install with: pip install DrissionPage\n")
    sys.exit(1)

# Load Environment
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent.parent / '.env')

# Setup Logging
log_file = Path(__file__).resolve().parent / 'tech_detector.log'
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
)

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# --- CPE MAP ---
CPE_MAP = {}
CPE_MAP_PATH = Path(__file__).resolve().parent / 'cpe_map.json'
try:
    if os.path.exists(CPE_MAP_PATH):
        with open(CPE_MAP_PATH, 'r') as f:
            raw_map = json.load(f)
            CPE_MAP = {k.lower(): v for k, v in raw_map.items()}
except Exception as e:
    logging.error(f"Gagal load cpe_map.json: {e}")

# --- HELPER FUNCTIONS ---

def normalize_software(raw):
    if not raw: return None
    clean_raw = re.sub(r'\([^\)]+\)', '', raw).strip().replace('/', ' ')
    match = re.search(r'([A-Za-z0-9\-\._]{2,})[ \t]+(\d+(\.\d+)+[a-z0-9\-]*)', clean_raw, re.IGNORECASE)
    if match:
        name = match.group(1).strip()
        ver = match.group(2).strip()
        if len(name) < 2 or name.isdigit(): return None
        return f"{name} {ver}"
    return None

def get_http_headers(url):
    try:
        r = requests.get(url, timeout=5, allow_redirects=True, stream=True)
        r.close() 
        return r.headers
    except: return {}

# --- FUNGSI DETEKSI (DRISSIONPAGE) ---

def detect_software(url):
    logging.info(f"Memulai deteksi (DrissionPage) pada: {url}")
    co = ChromiumOptions()
    co.headless(True)
    co.set_argument('--no-sandbox')
    co.set_argument('--disable-gpu')
    co.set_argument('--blink-settings=imagesEnabled=false')
    co.set_argument('--mute-audio')

    software_list = []
    page = None

    try:
        page = ChromiumPage(co)
        page.get(url)
        time.sleep(1.5)

        # 1. Meta Generator
        try:
            metas = page.eles('xpath://meta[@name="generator"]')
            for m in metas:
                c = m.attr('content')
                if c: software_list.append(c)
        except: pass

        # 2. Komentar HTML
        try:
            html_content = page.html
            comments = re.findall(r'', html_content, re.DOTALL)
            for c in comments:
                found = re.findall(r'(wordpress|joomla|drupal)[\s\-]?(\d+\.\d+(\.\d+)?)', c, re.IGNORECASE)
                for s in found:
                    software_list.append(f"{s[0]} {s[1]}")
        except: pass

        # 3. Script Src
        try:
            scripts = page.eles('tag:script')
            lib_patterns = {
                'jquery': r'jquery[-.]?(\d+\.\d+(\.\d+)?)',
                'moment': r'moment[-.]?(\d+\.\d+(\.\d+)?)',
                'bootstrap': r'bootstrap[-.]?(\d+\.\d+(\.\d+)?)',
                'vue': r'vue[-.]?(\d+\.\d+(\.\d+)?)',
                'react': r'react[-.]?(\d+\.\d+(\.\d+)?)',
                'angular': r'angular[-.]?(\d+\.\d+(\.\d+)?)',
                'chart.js': r'chart[-.]?(\d+\.\d+(\.\d+)?)'
            }
            for s in scripts:
                src = s.attr('src') or ""
                src_lower = src.lower()
                for lib, pattern in lib_patterns.items():
                    if lib in src_lower:
                        found = re.findall(pattern, src_lower)
                        for v in found:
                            software_list.append(f"{lib} {v[0]}")
        except: pass

        # 4. HTTP Headers
        headers = get_http_headers(url)
        for h in ['Server', 'X-Powered-By']:
            if h in headers:
                val = headers[h]
                parts = val.split(' ') 
                software_list.extend(parts)

        if page: page.quit()

        # 5. Normalisasi
        final_set = set()
        for item in software_list:
            norm = normalize_software(item)
            if norm: final_set.add(norm)
        
        return list(final_set)

    except Exception as e:
        logging.error(f"Error DrissionPage: {e}")
        if page: page.quit()
        return []

# --- FUNGSI CVE (FIXED: GET LATEST) ---

def search_cve(software_entry):
    try:
        parts = software_entry.split(" ", 1)
        if len(parts) < 2: return []
        
        name, ver_str = parts[0], parts[1]
        name = name.lower()
        
        if name not in CPE_MAP: return []

        base_cpe = CPE_MAP[name]
        if '<version>' in base_cpe:
            cpe = base_cpe.replace('<version>', ver_str)
        else:
            cpe = f"{base_cpe}:{ver_str}"

        time.sleep(1.0) # Rate Limit
        
        # PARAMETER PENTING UNTUK MENDAPATKAN CVE TERBARU
        # NVD tidak mendukung sorting "pubDate" langsung di endpoint CPE match,
        # tapi kita bisa memfilter berdasarkan tanggal publikasi agar tidak dapat sampah lama.
        # Kita ambil CVE dari 5 tahun terakhir saja.
        
        # start_date = (datetime.now() - timedelta(days=365*5)).strftime("%Y-%m-%dT%H:%M:%S.000")
        # end_date = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000")
        
        # NOTE: NVD API untuk CPE Match tidak support pubStartDate.
        # Jadi kita pakai trik: Ambil lebih banyak hasil (20), lalu sort manual di Python.
        
        params = {
            "cpeName": cpe, 
            "resultsPerPage": 30 # Naikkan limit agar CVE baru masuk
        }
        
        headers = {"Accept": "application/json"}
        if NVD_API_KEY: headers["apiKey"] = NVD_API_KEY

        logging.info(f"Checking NVD for: {cpe}")
        r = requests.get(NVD_API_URL, params=params, headers=headers, timeout=20)
        
        if r.status_code != 200:
            return []

        data = r.json()
        vulns = data.get("vulnerabilities", [])
        
        # Sorting manual di Python: Terbaru ke Terlama
        vulns.sort(key=lambda x: x['cve'].get('published', ''), reverse=True)
        
        # Ambil top 10 setelah sorting
        vulns = vulns[:10]
        
        results = []

        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            pub_date = cve.get("published", "")
            
            # Deskripsi
            descriptions = cve.get("descriptions", [])
            desc = next((d['value'] for d in descriptions if d['lang'] == 'en'), "No description")
            
            # Score
            metrics = cve.get("metrics", {})
            score = 0
            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            # --- FUNGSI SOLUSI DINAMIS ---
            def extract_solution(cve_data, software_name):
                references = cve_data.get("references", [])
                patch_links = []
                advisory_links = []
                for ref in references:
                    tags = ref.get("tags", [])
                    url = ref.get("url", "")
                    if "Patch" in tags: patch_links.append(url)
                    elif "Vendor Advisory" in tags: advisory_links.append(url)
                        
                if patch_links: return f"Terapkan Patch resmi: {patch_links[0]}"
                elif advisory_links: return f"Lihat Advisory: {advisory_links[0]}"
                return f"Perbarui {software_name} ke versi terbaru."

            dynamic_solution = extract_solution(cve, name)

            results.append({
                "cve_id": cve_id,
                "description": f"[{pub_date[:10]}] {desc}", # Tambahkan tanggal di deskripsi
                "cvss_score": score,
                "software": software_entry,
                "solution": dynamic_solution,
                "published": pub_date # Field baru untuk sorting di frontend
            })
            
        return results

    except Exception as e:
        logging.error(f"Gagal fetch CVE: {e}")
        return []

def search_cves_list(techs):
    all_cves = []
    for tech in techs:
        try:
            cves = search_cve(tech)
            if cves: all_cves.extend(cves)
        except: pass
    return all_cves

# --- MAIN ---

if __name__ == '__main__':
    try:
        if len(sys.argv) < 2:
            print(json.dumps({"error": "URL required"}))
            sys.exit(1)

        target = sys.argv[1]
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target

        # 1. Detect
        techs = detect_software(target)
        
        # 2. Search CVE
        cves = search_cves_list(techs)

        output = {
            "tech": techs,
            "cves": cves
        }
        print(json.dumps(output, indent=2))

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)