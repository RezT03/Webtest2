import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
import argostranslate.package
import argostranslate.translate
import sys
import time

# --- 1. SETUP LOGGER ---
# Logger akan mencatat ke file 'translation.log' dan juga tampil di terminal (Console)
logger = logging.getLogger("Translator")
logger.setLevel(logging.DEBUG)

# File Handler
file_handler = logging.FileHandler("translation.log", encoding='utf-8')
file_handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
logger.addHandler(file_handler)

# Stream Handler (Terminal)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
logger.addHandler(stream_handler)

app = Flask(__name__)
CORS(app)  # Izinkan akses dari Dashboard

# --- 2. AUTO INSTALL BAHASA (Optional) ---
def install_languages():
    logger.info("Memeriksa paket bahasa Argos Translate...")
    argostranslate.package.update_package_index()
    available_packages = argostranslate.package.get_available_packages()
    
    # Contoh: Install English -> Indonesian
    package_to_install = next(
        filter(
            lambda x: x.from_code == "en" and x.to_code == "id", available_packages
        ), None
    )
    
    if package_to_install:
        logger.info(f"Mengunduh dan menginstal bahasa: {package_to_install}")
        argostranslate.package.install_from_path(package_to_install.download())
        logger.info("Instalasi bahasa selesai.")
    else:
        logger.info("Paket bahasa (en->id) sudah terinstal atau tidak ditemukan.")

# Jalankan instalasi saat start (bisa dikomentari jika sudah ada)
try:
    install_languages()
except Exception as e:
    logger.error(f"Gagal setup bahasa: {e}")

# --- 3. ENDPOINT TRANSLATE DENGAN LOG ---
@app.route('/translate', methods=['POST'])
def translate_text():
    start_time = time.time()
    data = request.json
    
    # Ambil parameter
    q = data.get('q', [])
    source_lang = data.get('source', 'en')
    target_lang = data.get('target', 'id')

    # Normalisasi input (bisa string tunggal atau array)
    if isinstance(q, str):
        q = [q]
    
    if not q:
        logger.warning(f"Request kosong diterima dari {request.remote_addr}")
        return jsonify({"error": "No text provided"}), 400

    # Log Request Masuk
    logger.info(f"--- REQUEST BARU ---")
    logger.info(f"IP: {request.remote_addr} | Lang: {source_lang} -> {target_lang}")
    logger.info(f"Jumlah Teks: {len(q)} item")

    translated_results = []
    error_count = 0

    try:
        # Proses Translasi
        for i, text in enumerate(q):
            try:
                # Log sampel teks (potong jika terlalu panjang agar log rapi)
                snippet = (text[:50] + '...') if len(text) > 50 else text
                logger.debug(f"[{i+1}/{len(q)}] Translating: '{snippet}'")

                # Eksekusi Argos Translate
                translated = argostranslate.translate.translate(text, source_lang, target_lang)
                translated_results.append(translated)
            except Exception as e:
                logger.error(f"Gagal translate item ke-{i+1}: {e}")
                translated_results.append(text) # Fallback ke teks asli
                error_count += 1

        # Hitung durasi
        duration = time.time() - start_time
        
        # Log Hasil Akhir
        if error_count > 0:
            logger.warning(f"Selesai dengan {error_count} error. Waktu: {duration:.2f}s")
        else:
            logger.info(f"Sukses menerjemahkan {len(q)} item. Waktu: {duration:.2f}s")

        return jsonify({
            "translatedText": translated_results if len(translated_results) > 1 else translated_results[0]
        })

    except Exception as server_error:
        logger.critical(f"Critical Error di Endpoint Translate: {server_error}")
        return jsonify({"error": str(server_error)}), 500

if __name__ == '__main__':
    logger.info("Menjalankan Server Translasi di port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=False)