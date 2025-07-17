FROM node:22

# Install Python & pip
RUN apt-get update && apt-get install -y python3 python3-pip

# Set workdir
WORKDIR /app
# copy node environment
COPY ./package*.json ./
# Copy backend files
COPY . .

# Install backend dependencies
RUN npm install

#jalankan python dulu
RUN apt-get update && apt-get install python3.11-venv -y
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

#Headless browser
RUN apt-get update && apt-get install -y \
    chromium \
    chromium-driver \
    libnss3 \
    libxss1 \
    libasound2 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libgbm1 \
    libgtk-3-0 \
    libdrm2 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    fonts-liberation \
    xdg-utils \
    ca-certificates \
    && apt-get clean

# install requirements.txt
COPY backend/utils/requirements.txt ./utils/requirements.txt
RUN pip install -r ./utils/requirements.txt

#Install slowhttptes
RUN apt-get update && apt-get install -y slowhttptest

# Expose port (ganti sesuai port backend Anda)
EXPOSE 3001

#app.js workdir
WORKDIR /app/backend

# Jalankan backend
CMD ["node", "app.js"]