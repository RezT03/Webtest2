# ==========================================
# STAGE 1: Node.js Builder (Untuk install modul npm)
# ==========================================
FROM node:22-slim AS node_builder

WORKDIR /app

# Copy file package manager
COPY package*.json ./
# Jika ada package.json di backend, copy juga (sesuaikan struktur Anda)
# COPY backend/package*.json ./backend/

# Install dependencies (Hanya production untuk menghemat size)
# Kita install semua dulu agar 'concurrently' jalan, nanti di pruning
RUN npm install

# ==========================================
# STAGE 2: Final Image (Python + System Tools)
# ==========================================
FROM python:3.11-slim-bookworm

# Set Environment Variables agar Python & Docker lebih optimal
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    # Konfigurasi lokasi Chrome untuk DrissionPage
    CHROME_BIN=/usr/bin/chromium \
    CHROMEDRIVER_PATH=/usr/bin/chromedriver

WORKDIR /app

# 1. Install System Dependencies (Layer ini di-cache)
# - openjdk-17-jre: Wajib untuk ZAP
# - nmap: Wajib untuk Nmap Scan
# - chromium & driver: Wajib untuk DrissionPage
# - nodejs & npm: Wajib untuk menjalankan server Express
# - curl/wget: Untuk download ZAP
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre \
    nmap \
    chromium \
    chromium-driver \
    nodejs \
    npm \
    wget \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 2. Install ZAP (Download otomatis agar tidak perlu upload folder besar)
# Kita download versi 2.16.0 (atau sesuaikan) dan ekstrak ke /app/ZAP_2.16.1
# Ini penting agar path ZAPScanner.py Anda ("../../ZAP_2.16.1/zap.sh") tetap valid.
# ARG ZAP_VERSION=2.16.0
# RUN wget -q https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz \
#     && tar -xzf ZAP_${ZAP_VERSION}_Linux.tar.gz \
#     && mv ZAP_${ZAP_VERSION} ZAP_2.16.1 \
#     && rm ZAP_${ZAP_VERSION}_Linux.tar.gz

# 3. Install Python Dependencies
COPY backend/utils/requirements.txt ./backend/utils/

# OPTIMASI UKURAN: Gunakan PyTorch versi CPU (Hemat ~700MB dibanding versi GPU)
# Kita install torch cpu secara eksplisit sebelum requirements lainnya
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir -r backend/utils/requirements.txt

# 4. Copy Project Files
# Copy node_modules dari Stage 1
COPY --from=node_builder /app/node_modules ./node_modules
# Copy seluruh kode sumber aplikasi
COPY . .

# 5. Setup Permissions (Opsional, tapi baik untuk keamanan)
# chmod zap.sh agar bisa dieksekusi
# RUN chmod +x ZAP_2.16.1/zap.sh

# 6. Expose Ports
# 3001: Dashboard Node.js
# 5000: LibreTranslate (Flask)
EXPOSE 3001 5000

# 7. Start Command
# Menjalankan npm run dev (concurrently node & python)
CMD ["npm", "run", "dev"]