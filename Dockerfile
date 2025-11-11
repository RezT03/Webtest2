# ---------- STAGE 1: BUILDER (membangun wheel dan assets)
FROM node:20-slim AS builder
ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /build

# Install paket sistem yang mungkin diperlukan untuk membangun dependensi Python/Node
# (Catatan: ini hanya di stage builder — tidak ikut ke runtime)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    build-essential \
    gcc \
    g++ \
    make \
    curl \
    ca-certificates \
    git \
 && rm -rf /var/lib/apt/lists/*

# Copy hanya file requirements dan package.json untuk memanfaatkan cache Docker
COPY backend/utils/requirements.txt ./utils/requirements.txt
COPY package.json package-lock.json ./   # jika project root memiliki package.json (sesuaikan path)

# Build Python wheels (jika ada dependensi yang perlu dikompile)
RUN pip3 wheel --no-cache-dir --wheel-dir /wheels -r ./utils/requirements.txt

# Install node modules & build frontend/backend assets if needed (optional)
# Jika aplikasi Anda tidak mempunyai step npm build, baris berikut tidak berpengaruh.
COPY . .
RUN if [ -f package.json ]; then npm ci --silent --no-audit --no-fund || true; fi
# Jika Anda punya script build (mis: npm run build), jalankan di sini:
# RUN if [ -f package.json ] && grep -q "\"build\"" package.json; then npm run build; fi

# ---------- STAGE 2: RUNTIME (lebih ramping, berisi runtime packages yang sama seperti Dockerfile asli) ----------
FROM node:20-slim AS runtime
ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /app

# Install paket runtime yang sama seperti yang Anda gunakan (pertahankan dependency)
# Jika Dockerfile asli Anda punya paket tambahan, tambahkan di sini.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    chromium \
    chromium-driver \
    openjdk-17-jre-headless \
    slowhttptest \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Copy built wheels dari builder dan install packages dari wheels untuk menghindari compile ulang
COPY --from=builder /wheels /wheels
COPY backend/utils/requirements.txt ./utils/requirements.txt
RUN if [ -d /wheels ]; then pip3 install --no-index --no-cache-dir --find-links=/wheels -r ./utils/requirements.txt || pip3 install --no-cache-dir -r ./utils/requirements.txt; else pip3 install --no-cache-dir -r ./utils/requirements.txt; fi

# Salin hanya file yang diperlukan ke image runtime (hindari copy . secara keseluruhan)
# Sesuaikan paths berikut dengan struktur proyek Anda
COPY backend/ ./backend/
# Jika ada frontend build artifacts (dari builder), salin dari builder jika diperlukan:
# COPY --from=builder /build/dist ./frontend/dist

# Set working dir sesuai entrypoint original Anda (lihat Dockerfile awal)
WORKDIR /app/backend

# Expose port yang diperlukan
EXPOSE 3001

ENV PYTHONUNBUFFERED=1
ENV NODE_ENV=production

# Jalankan aplikasi: tetap menggunakan perintah yang sama seperti di Dockerfile anda
CMD ["node", "app.js"]
