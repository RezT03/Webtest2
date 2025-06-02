from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import re
import requests
import os
from dotenv import load_dotenv
from pathlib import Path
load_dotenv(dotenv_path="../.env")
env_path = Path(__file__).resolve().parent.parent.parent / '.env'
load_dotenv(dotenv_path=env_path)

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_http_headers(url):
    try:
        r = requests.get(url, timeout=5)
        return r.headers
    except:
        return {}

def detect_software(url):
    options = Options()
    options.headless = True
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    driver = webdriver.Chrome(options=options)
    driver.get(url)
    soup = BeautifulSoup(driver.page_source, 'html.parser')
    driver.quit()

    software_list = []

    # Meta generator
    meta_gen = soup.find('meta', attrs={'name': 'generator'})
    if meta_gen:
        software_list.append(meta_gen['content'])

    # Komentar HTML
    comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text)
    for c in comments:
        found = re.findall(r'(wordpress|joomla|drupal|woocommerce|spothub|wix|ghost|magneto|cdnjs|cloudflare)[\s\-]?(\d+\.\d+(\.\d+)?)', c, re.IGNORECASE)
        for s in found:
            software_list.append(f"{s[0]} {s[1]}")

    # Script includes (JS libraries)
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
    headers = get_http_headers(url)
    if 'Server' in headers:
        software_list.append(f"server {headers['Server']}")
    if 'X-Powered-By' in headers:
        software_list.append(f"x-powered-by {headers['X-Powered-By']}")
    
    print("Terdeteksi:", software_list)

    for sw in software_list:
        print(f"Mengecek CVE untuk: {sw}")
    cves = search_cve(sw)
    if not cves:
        print(f"Tidak ada CVE ditemukan untuk: {sw}")
    else:
        for c in cves:
            print(f"{c['cve_id']} - {c['description']}\nSolusi: {c['solution']}")
            
    return list(set(software_list))
    

def search_cve(software_entry):
    headers = {"apiKey": NVD_API_KEY}
    keyword = software_entry.replace(" ", "+")
    params = {"keywordSearch": keyword, "resultsPerPage": 5}
    r = requests.get(NVD_API_URL, headers=headers, params=params)
    if r.status_code != 200:
        return None
    items = r.json().get("vulnerabilities", [])
    return [
        {
            "cve_id": i['cve']['id'],
            "description": i['cve']['descriptions'][0]['value'],
            "software": software_entry
        }
        for i in items if 'cve' in i
    ]

if __name__ == '__main__':
    import sys
    target = sys.argv[1]
    techs = detect_software(target)
    all_cves = []
    for t in techs:
        cves = search_cve(t)
        if cves:
            all_cves.extend(cves)

    for c in all_cves:
        print(f"{c['software']} - {c['cve_id']}: {c['description']}\n---")
        
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

def search_cve(software_entry):
    headers = {"apiKey": NVD_API_KEY}
    keyword = software_entry.replace(" ", "+")
    params = {"keywordSearch": keyword, "resultsPerPage": 5}
    r = requests.get(NVD_API_URL, headers=headers, params=params)
    if r.status_code != 200:
        return None
    items = r.json().get("vulnerabilities", [])
    results = []
    for i in items:
        if 'cve' in i:
            cve_id = i['cve']['id']
            desc = i['cve']['descriptions'][0]['value']
            refs = i['cve'].get('references', [])
            patches = [r['url'] for r in refs if 'Patch' in r.get('tags', [])]
            solution = patches[0] if patches else generate_generic_solution(desc)
            results.append({
                "cve_id": cve_id,
                "description": desc,
                "software": software_entry,
                "solution": solution
            })
    return results



#utils/pdf_exporter.py (tambahkan DoS analisis jika ditemukan)
