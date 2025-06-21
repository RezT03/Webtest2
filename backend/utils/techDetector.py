from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from bs4 import BeautifulSoup
import re
import requests
import os
import logging
from pathlib import Path
from dotenv import load_dotenv
import time
import sys
import json
from packaging import version

# Load .env dari root
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent.parent / '.env')

# Setup logging
log_file = Path(__file__).resolve().parent / 'tech_detector.log'
logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s: %(message)s',
)

logging.info("=== Memulai scanning teknologi ===")

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DB_CONFIG = {
    'host': os.getenv("DB_HOST", "localhost"),
    'user': os.getenv("DB_USER", "root"),
    'password': os.getenv("DB_PASS", ""),
    'database': os.getenv("DB_NAME", "websec")
}

CPE_MAP_PATH = Path(__file__).resolve().parent / 'cpe_map.json'
with open(CPE_MAP_PATH, 'r') as f:
    CPE_MAP = json.load(f)

def search_cve(software_entry):
    try:
        # Parsing software entry
        if " " not in software_entry:
            logging.debug(f"Invalid software entry format: {software_entry}")
            return []
        name, version_str = software_entry.split(" ", 1)
        if name not in CPE_MAP:
            logging.debug(f"CPE tidak tersedia untuk: {name}")
            return []

        # Generate CPE
        base_cpe = CPE_MAP[name]
        if '*' in base_cpe:
            cpe = base_cpe.replace('<version>', version_str)
        else:
            cpe = f"{base_cpe}:{version_str}"

        # Query NVD API
        params = {
            "cpeName": cpe,
            "resultsPerPage": 10
        }
        headers = {"Accept": "application/json"}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        r = requests.get(NVD_API_URL, params=params, headers=headers)
        logging.debug(f"CVE search for {cpe}: status {r.status_code}")
        
        if r.status_code != 200:
            logging.warning(f"CVE lookup gagal: {r.status_code}")
            return []

        # Parse response
        json_data = r.json()
        # Ambil vulnerabilities dari response
        vulnerabilities = json_data.get("vulnerabilities", [])
        results = []

        for vuln in vulnerabilities:
            try:
                cve = vuln.get("cve", {})
                if not cve:
                    continue

                cve_id = cve.get("id")
                descriptions = cve.get("descriptions", [])
                desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")

                if not cve_id or not desc:
                    continue

                # Perbaikan parsing configurations
                configs = []
                for config in cve.get("configurations", []):
                    configs.extend(config.get("nodes", []))
                is_affected = False

                for config in configs:
                    for cpe_match in config.get("cpeMatch", []):
                        if not cpe_match.get("vulnerable", False):
                            continue

                        current_version = version.parse(version_str)
                        v_start = cpe_match.get("versionStartIncluding") or cpe_match.get("versionStartExcluding")
                        v_end = cpe_match.get("versionEndIncluding") or cpe_match.get("versionEndExcluding")

                        # Simple version check
                        if v_start and version.parse(v_start) <= current_version:
                            if v_end and current_version <= version.parse(v_end):
                                is_affected = True
                                break
                        elif v_end and current_version <= version.parse(v_end):
                            is_affected = True
                            break
                        elif not v_start and not v_end:
                            is_affected = True
                            break

                if is_affected:
                    results.append({
                        "cve_id": cve_id,
                        "description": desc,
                        "software": software_entry,
                        "solution": generate_generic_solution(desc)
                    })

            except Exception as e:
                logging.warning(f"Error processing vulnerability: {str(e)}")
                continue

        return results

    except Exception as e:
        logging.error(f"Gagal fetch CVE: {str(e)}")
        return []

def fetch_cve(cpe_name):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_name}&resultsPerPage=10"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        cves_data = []
        if 'vulnerabilities' in data and isinstance(data['vulnerabilities'], list):
            for vulnerability_item in data['vulnerabilities']:
                cve_info = vulnerability_item.get('cve', {})
                
                # Get CVE details
                cve_id = cve_info.get('id', 'N/A')
                descriptions = cve_info.get('descriptions', [])
                english_description = next(
                    (desc['value'] for desc in descriptions if desc.get('lang') == 'en'), 
                    'No description available'
                )
                
                # Add to results if valid
                if cve_id != 'N/A':
                    cves_data.append({
                        'id': cve_id,
                        'description': english_description,
                        'lastModified': cve_info.get('lastModified', 'N/A'),
                        'published': cve_info.get('published', 'N/A'),
                        'severity': cve_info.get('baseSeverity', 'N/A')
                    })

        return cves_data

    except requests.exceptions.RequestException as e:
        logging.error(f"Network error in fetch_cve: {str(e)}")
        return []
    except json.JSONDecodeError as e:
        logging.error(f"JSON decode error in fetch_cve: {str(e)}")
        return []
    except Exception as e:
        logging.error(f"Unexpected error in fetch_cve: {str(e)}")
        return []
# Di bagian __main__ / pemanggilan
def get_http_headers(url):
    try:
        r = requests.get(url, timeout=5)
        return r.headers
    except Exception as e:
        logging.error(f"Gagal mengambil header: {str(e)}")
        return {}

def normalize_software(raw):
    match = re.match(r'([A-Za-z\-]+)[/ ]?(\d+\.\d+(\.\d+)?)', raw)
    if match:
        name = match.group(1)
        version = match.group(2)
        return f"{name} {version}"
    return raw

def detect_software(url):
    options = Options()
    options.headless = True
    options.add_argument('--headless=new')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.binary_location = "/usr/bin/chromium-browser"

    try:
        service = Service(executable_path="/usr/bin/chromedriver")
        driver = webdriver.Chrome(service=service, options=options)
        
        driver.get(url)
        time.sleep(3)  # beri waktu JS merender

        try:
            with open(Path(__file__).resolve().parent / 'last_page_source.html', 'w', encoding='utf-8') as f:
                f.write(driver.page_source)
                logging.debug("✅ HTML hasil render disimpan ke last_page_source.html")
        except Exception as e:
            logging.warning(f"Gagal simpan HTML: {str(e)}")

        soup = BeautifulSoup(driver.page_source, 'html.parser')
        driver.quit()

        software_list = []
        headers = get_http_headers(url)

        # Deteksi meta generator
        meta_gen = soup.find('meta', attrs={'name': 'generator'})
        if meta_gen:
            software_list.append(meta_gen['content'])

        # Komentar HTML
        comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text)
        for c in comments:
            found = re.findall(r'(wordpress|joomla|drupal)[\s\-]?(\d+\.\d+(\.\d+)?)', c, re.IGNORECASE)
            for s in found:
                software_list.append(f"{s[0]} {s[1]}")

        # Script includes
        scripts = soup.find_all('script', src=True)
        for s in scripts:
            src = s['src']
            lib_versions = {
                'jquery': r'jquery[-.]?(\d+\.\d+(\.\d+)?)',
                'moment': r'moment[-.]?(\d+\.\d+(\.\d+)?)',
                'bootstrap': r'bootstrap[-.]?(\d+\.\d+(\.\d+)?)'
            }
            for lib, pattern in lib_versions.items():
                if lib in src:
                    found = re.findall(pattern, src)
                    for v in found:
                        software_list.append(f"{lib} {v[0]}")
        
        # HTTP Headers
        if 'Server' in headers:
            header_val = headers['Server']
            parts = re.split(r'(?<!:)[\s,]+', header_val)
            software_list.extend(parts)
        if 'X-Powered-By' in headers:
            header_val = headers['X-Powered-By']
            parts = re.split(r'(?<!:)[\s,]+', header_val)
            software_list.extend(parts)

        # Deteksi moment.js dari inline script
        for script in soup.find_all('script'):
            if script.string and 'moment' in script.string:
                software_list.append('moment (inline)')

        # Normalisasi dan deduplikasi hasil
        software_list = list(set(software_list))
        logging.debug(f"Software sebelum normalisasi: {software_list}")
        software_list = [normalize_software(s) for s in software_list]
        logging.debug(f"Software setelah normalisasi: {software_list}")
        return software_list

    except Exception as e:
        logging.error(f"Error dalam detect_software: {str(e)}")
        return []
    
def check_csrf_token(soup, headers):
    found = False
    # Input hidden dengan nama mengandung csrf
    hidden_inputs = soup.find_all('input', {'type': 'hidden'})
    for inp in hidden_inputs:
        if 'name' in inp.attrs and re.search("csrf", inp['name'], re.IGNORECASE):
            return True

    # Meta tag
    meta = soup.find_all('meta', {'name': re.compile('csrf', re.IGNORECASE)})
    if meta:
        return True

    # Header
    for k in headers:
        if re.search('csrf', k, re.IGNORECASE):
            return True

    # Inline JS
    scripts = soup.find_all('script')
    for s in scripts:
        if s.string and re.search(r'(csrfToken|_csrf|XSRF)', s.string, re.IGNORECASE):
            return True

    return False


def generate_generic_solution(description):
    desc = description.lower()
    if 'sql injection' in desc:
        return 'Gunakan parameterized query atau ORM, hindari concatenation SQL.'
    elif 'xss' in desc:
        return 'Escape output HTML dan gunakan CSP (Content Security Policy).'
    elif 'csrf' in desc:
        return 'Gunakan token CSRF dan validasi origin referer header.'
    elif 'rce' in desc or 'remote code execution' in desc:
        return 'Batasi input pengguna dan patch library eksekusi kode.'
    elif 'directory traversal' in desc:
        return 'Validasi path input dan gunakan fungsi path normalisasi.'
    elif 'dos' in desc or 'denial of service' in desc:
        return 'Gunakan rate limiting, CDN, dan deteksi anomali trafik.'
    elif 'leak' in desc or 'disclosure' in desc:
        return 'Batasi informasi error dan gunakan environment production.'
    else:
        return 'Perbarui software atau versi library sesuai rekomendasi vendor.'

def normalize_software(raw):
    raw = raw.replace('/', ' ')  # ganti '/' dengan spasi
    match = re.match(r'([A-Za-z\-]+)[ ]?(\d+\.\d+(\.\d+)?[a-z]?)', raw)
    if match:
        name = match.group(1)
        version = match.group(2)
        return f"{name} {version}"
    return raw

def search_cve_by_cpe(software_name, version_str):
    original_name = software_name
    software_name = software_name.lower()
    base_cpe = CPE_MAP.get(software_name)
    if not base_cpe:
        logging.debug(f"Tidak ada CPE untuk: {software_name}")
        return []

    if '<version>' in base_cpe:
        cpe = base_cpe.replace('<version>', version_str)
    else:
        cpe = f"{base_cpe}:{version_str}"

    logging.debug(f"🔍 Query CVE NVD untuk CPE: {cpe}")
    try:
        params = {
            "cpeName": cpe,
            "resultsPerPage": 20
        }
        headers = {
            "Accept": "application/json"
        }
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        r = requests.get(NVD_API_URL, params=params, headers=headers)  # [FIX: pakai header bukan query]
        if r.status_code != 200:
            logging.warning(f"Gagal mengakses NVD: {r.status_code} {r.text[:200]}")
            return []

        try:
            json_data = r.json()
            if isinstance(json_data, list):  # [FIX: tangani jika JSON berupa list]
                logging.error("❌ Respons JSON berupa list, bukan dict. Struktur tidak valid.")
                return []
            if "vulnerabilities" not in json_data:
                logging.warning("⚠️ Tidak ditemukan 'vulnerabilities' dalam respons JSON.")
                return []
            data = json_data["vulnerabilities"]
        except Exception as e:
            logging.error(f"❌ Error saat parsing JSON respons NVD: {e}")
            return []

        result = []

        for item in data:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            desc = cve.get("descriptions", [{}])[0].get("value", "")
            configurations = cve.get("configurations", {}).get("nodes", [])

            for node in configurations:
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable", False):
                        continue

                    v_start = cpe_match.get("versionStartIncluding") or cpe_match.get("versionStartExcluding")
                    v_end = cpe_match.get("versionEndIncluding") or cpe_match.get("versionEndExcluding")
                    current_version = version.parse(version_str)
                    affected = False

                    if v_start and v_end:
                        affected = (version.parse(v_start) <= current_version)
                        affected &= (current_version < version.parse(v_end))
                    elif v_start:
                        affected = current_version >= version.parse(v_start)
                    elif v_end:
                        affected = current_version < version.parse(v_end)
                    else:
                        affected = True

                    if affected:
                        result.append({
                            "software": f"{original_name} {version_str}",
                            "cve_id": cve_id,
                            "description": desc,
                            "solution": "Perbarui ke versi terbaru yang tersedia."
                        })

        return result
    except Exception as e:
        logging.error(f"Gagal fetch CVE: {str(e)}")
        return []
    
def search_cves_list(techs):
    logging.info("\nMencari CVE untuk teknologi yang terdeteksi...")
    all_cves = []
    for tech in techs:
        try:
            logging.info(f"\n📊 Analyzing: {tech}")
            cves = search_cve(tech)
            if cves:
                all_cves.extend(cves)
                logging.info(f"✅ Found {len(cves)} CVE(s):")
        except Exception as e:
            logging.info(f"❌ Error saat mencari CVE untuk {tech}: {e}")
    return all_cves

def search_cves_combined(software_list):
    all_cves = []
    for entry in software_list:
        parts = entry.split(" ", 1)
        if len(parts) != 2:
            logging.warning(f"❌ Tidak bisa parsing entri software: {entry}")
            continue
        name, ver = parts
        logging.debug(f"▶️ Mendeteksi CVE untuk: {name} {ver}")
        cves = search_cve_by_cpe(name, ver)
        if cves:
            all_cves.extend(cves)
    return all_cves

if __name__ == '__main__':
    try:
        # Validasi argumen
        if len(sys.argv) < 2:
            logging.info("Error: URL tidak diberikan")
            logging.info("Penggunaan: python techDetector.py <url>")
            sys.exit(1)

        target = sys.argv[1]
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target

        logging.info(f"🔍 Mendeteksi teknologi pada: {target}")
        logging.info(f"Memulai scan pada: {target}")

        # Deteksi teknologi
        techs = detect_software(target)
        all_cves = []
        
        if not techs:
            logging.info("❌ Tidak ada teknologi yang terdeteksi.")
            logging.warning("Tidak ada teknologi yang berhasil dideteksi.")
            sys.exit(0)
        
        logging.info("\n✅ Teknologi terdeteksi:")
        for tech in techs:
            logging.info(f"   • {tech}")

        # Cari CVE untuk setiap teknologi
        logging.info("\n🔍 Mencari CVE untuk teknologi yang terdeteksi...")
        for tech in techs:
            try:
                logging.info(f"\n📊 Analyzing: {tech}")
                cves = search_cve(tech)
                if cves:
                    all_cves.extend(cves)
                    logging.info(f"   Found {len(cves)} CVE(s):")
                    for c in cves:
                        logging.info(f"\n   • {c['cve_id']}")
                        logging.info(f"     Description: {c['description']}")
                        logging.info(f"     Solution: {c['solution']}")
                else:
                    logging.info(f"   ✓ No CVEs found for {tech}")
            except Exception as e:
                logging.error(f"Error scanning {tech}: {str(e)}")
                logging.info(f"   ⚠️ Error scanning {tech}")
                continue

        # Summary
        logging.info(f"\n📝 Summary:")
        logging.info(f"   • Technologies detected: {len(techs)}")
        logging.info(f"   • Total CVEs found: {len(all_cves)}")

    except KeyboardInterrupt:
        logging.info("\n⚠️ Scan cancelled by user")
        logging.warning("Scan dibatalkan oleh user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Critical error: {str(e)}")
        logging.info(f"\n❌ Error: {str(e)}")
        sys.exit(1)