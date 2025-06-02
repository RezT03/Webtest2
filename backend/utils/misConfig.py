import requests
from urllib.parse import urljoin

def check_headers(url):
    try:
        res = requests.get(url)
        issues = []

        if 'X-Frame-Options' not in res.headers:
            issues.append("Header X-Frame-Options tidak ada (rawan clickjacking)")
        if 'Content-Security-Policy' not in res.headers:
            issues.append("Header CSP tidak ada (rawan XSS)")
        if 'X-XSS-Protection' not in res.headers:
            issues.append("Header X-XSS-Protection tidak ada")
        if 'Server' in res.headers:
            issues.append(f"Server mengungkapkan detail: {res.headers['Server']}")

        return issues
    except Exception as e:
        return [f"Gagal cek header: {str(e)}"]

def check_http_methods(url):
    try:
        methods = ['OPTIONS', 'TRACE', 'PUT', 'DELETE']
        issues = []
        for method in methods:
            r = requests.request(method, url, timeout=3)
            if r.status_code < 400:
                issues.append(f"Metode HTTP {method} diizinkan, berisiko.")
        return issues
    except Exception as e:
        return [f"Gagal cek metode HTTP: {str(e)}"]

if __name__ == '__main__':
    import sys
    target = sys.argv[1]
    print("\n".join(check_headers(target) + check_http_methods(target)))