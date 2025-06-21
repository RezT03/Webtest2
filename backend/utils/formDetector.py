import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import logging

logging.basicConfig(level=logging.INFO)

def extract_form_parameters(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        parameters = []

        for form in forms:
            form_details = {
                "action": urljoin(url, form.get("action")) if form.get("action") else url,
                "method": form.get("method", "get").lower(),
                "inputs": []
            }
            for input_tag in form.find_all("input"):
                name = input_tag.get("name")
                input_type = input_tag.get("type", "text")
                value = input_tag.get("value", "")
                if name:
                    form_details["inputs"].append({
                        "name": name,
                        "type": input_type,
                        "value": value
                    })
            parameters.append(form_details)

        logging.info(f"🧾 Total form ditemukan di {url}: {len(parameters)}")
        return parameters

    except Exception as e:
        logging.error(f"❌ Gagal ekstrak form: {e}")
        return []