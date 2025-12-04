# Stage 1: Node.js Builder
FROM node:22-slim AS node_builder
WORKDIR /app
COPY package*.json ./
RUN npm install --production

# Stage 2: Final Image
FROM python:3.11-alpine
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    CHROME_BIN=/usr/bin/chromium \
    CHROMEDRIVER_PATH=/usr/bin/chromedriver
WORKDIR /app
RUN apk add --no-cache \
    chromium \
    chromium-chromedriver \
    openjdk17 \
    nmap \
    curl \
    && rm -rf /var/cache/apk/*
COPY backend/utils/requirements.txt ./backend/utils/
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir -r backend/utils/requirements.txt
COPY --from=node_builder /app/node_modules ./node_modules
COPY . .
EXPOSE 3001 5000
CMD ["npm", "run", "dev"]
