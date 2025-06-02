import requests
from libretranslatepy import LibreTranslateAPI

def fetch_cve_data(keyword):
    r = requests.get(f'https://cve.circl.lu/api/search/{keyword}')
    if not r.ok:
        return []
    data = r.json()
    lt = LibreTranslateAPI()
    results = []
    for item in data.get('data', [])[:5]:
        desc_id = lt.translate(item['summary'], 'en', 'id')
        results.append({
            'cve_id': item['id'],
            'description_en': item['summary'],
            'description_id': desc_id,
            'solution': 'Lakukan update software atau patch yang direkomendasikan.',
            'software': keyword
        })
    return results

if __name__ == '__main__':
    import sys
    keyword = sys.argv[1]
    data = fetch_cve_data(keyword)
    for d in data:
        print(f"{d['cve_id']}\n{d['description_id']}\n{d['solution']}\n---")
