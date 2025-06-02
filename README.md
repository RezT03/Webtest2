# 🔒 WebSecGuard - Web Security Testing Platform

> Aplikasi web komprehensif untuk melakukan pengujian keamanan website dengan berbagai teknik dan metodologi penetration testing.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Rating](https://img.shields.io/badge/Security-A+-green.svg)](https://github.com/RezT03/Websec2)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.com/RezT03/Websec2)

## 🎯 Tentang Aplikasi

WebSec2 adalah platform pengujian keamanan web yang dirancang untuk membantu penetration testers, dan developers dalam mengidentifikasi vulnerability pada aplikasi web. Aplikasi ini menyediakan berbagai tools dan teknik testing yang terintegrasi dalam satu interface yang user-friendly.

## ✨ Fitur Utama

### 🔍 Vulnerability Scanning

- **SQL Injection Detection** - Deteksi otomatis celah SQL injection
- **XSS Testing** - Cross-Site Scripting vulnerability assessment
- **CSRF Protection Check** - Validasi mekanisme CSRF protection
- **Directory Traversal** - Path traversal vulnerability scanning
- **File Upload Security** - Analisis keamanan file upload functionality

### 🌐 Web Application Analysis

- **Port Scanning** - Network port enumeration dan service detection
- **SSL/TLS Assessment** - Evaluasi konfigurasi SSL/TLS dan cipher suites
- **Header Security Analysis** - Pemeriksaan HTTP security headers
- **Cookie Security** - Analisis konfigurasi dan keamanan cookies
- **Authentication Testing** - Evaluasi mekanisme autentikasi

### 📊 Reporting & Analytics

- **Detailed Reports** - Laporan vulnerability dengan prioritas dan rekomendasi
- **Export Functionality** - Export hasil dalam format PDF, HTML, dan JSON
- **Risk Assessment** - Penilaian tingkat risiko berdasarkan OWASP standards
- **Timeline Tracking** - Pelacakan progress remediation

## 🚀 Quick Start

### Prerequisites

```bash
# Node.js 18+ required
node --version

# Python 3.8+ required
python --version

# Docker (optional)
docker --version
```

### Installation

1. **Clone Repository**

```bash
git clone https://github.com/yourusername/websecguard.git
cd websecguard
```

2. **Install Dependencies**

```bash
# Frontend dependencies
npm install

# Backend dependencies
cd backend
pip install -r requirements.txt
```

3. **Environment Setup**

```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

4. **Database Setup**

```bash
# Run database migrations
python manage.py migrate

# Create admin user
python manage.py createsuperuser
```

5. **Start Application**

```bash
# Start backend server
python manage.py runserver

# Start frontend (new terminal)
npm start
```

Aplikasi akan tersedia di `http://localhost:3000`

## 🔧 Konfigurasi

### Environment Variables

```env
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=websecguard
DB_USER=your_username
DB_PASSWORD=your_password

# Security Settings
SECRET_KEY=your-secret-key-here
ALLOWED_HOSTS=localhost,127.0.0.1

# API Keys (optional)
SHODAN_API_KEY=your-shodan-key
VIRUSTOTAL_API_KEY=your-virustotal-key
```

### Custom Payloads

Anda dapat menambahkan custom payloads untuk testing:

```json
{
  "sql_injection": [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "1' UNION SELECT NULL,NULL,NULL--"
  ],
  "xss_payloads": [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')"
  ]
}
```

## 📖 Panduan Penggunaan

### 1. Target Setup

```bash
# Tambahkan target untuk testing
curl -X POST http://localhost:8000/api/targets/ \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "name": "Test Target"}'
```

### 2. Vulnerability Scan

```bash
# Jalankan scan komprehensif
curl -X POST http://localhost:8000/api/scan/ \
  -H "Content-Type: application/json" \
  -d '{"target_id": 1, "scan_type": "full"}'
```

### 3. View Results

```bash
# Dapatkan hasil scan
curl http://localhost:8000/api/results/1/
```

## 🛡️ Security Features

- **Authentication & Authorization** - Multi-level user access control
- **Rate Limiting** - Protection against abuse dan DoS attacks
- **Input Validation** - Comprehensive input sanitization
- **Secure Headers** - Implementation of security headers
- **Audit Logging** - Detailed logging untuk compliance

## 🔬 Testing Methodologies

Aplikasi ini mengimplementasikan metodologi testing berdasarkan:

- **OWASP Top 10** - Coverage untuk semua kategori vulnerability
- **NIST Cybersecurity Framework** - Structured approach untuk security testing
- **PTES (Penetration Testing Execution Standard)** - Comprehensive testing methodology
- **OSSTMM** - Open Source Security Testing Methodology Manual

## 📊 Supported Vulnerability Types

| Category | Vulnerability Type | Detection Method |
|----------|-------------------|------------------|
| Injection | SQL Injection | Pattern matching + Blind testing |
| Injection | NoSQL Injection | MongoDB/CouchDB specific payloads |
| XSS | Reflected XSS | Dynamic payload injection |
| XSS | Stored XSS | Persistent payload testing |
| Broken Auth | Weak Passwords | Dictionary attacks |
| Broken Auth | Session Fixation | Session management testing |
| Sensitive Data | Unencrypted Data | Traffic analysis |
| XML | XXE Injection | XML external entity testing |
| Broken Access | IDOR | Object reference manipulation |
| Security Misconfig | Default Credentials | Common credential testing |

## 🚨 Disclaimer

**PERINGATAN PENTING:** Aplikasi ini dirancang untuk tujuan educational dan authorized penetration testing. Penggunaan tools ini pada sistem yang bukan milik Anda tanpa izin eksplisit adalah **ILEGAL** dan dapat mengakibatkan konsekuensi hukum.

### Penggunaan yang Diizinkan

- ✅ Testing pada sistem milik sendiri
- ✅ Authorized penetration testing dengan written permission
- ✅ Educational purposes dalam controlled environment
- ✅ Bug bounty programs dengan proper scope

### Penggunaan yang Dilarang

- ❌ Unauthorized access ke sistem orang lain
- ❌ Malicious attacks atau damage
- ❌ Testing tanpa explicit permission
- ❌ Violation of terms of service

## 🤝 Contributing

Kami menyambut kontribusi dari komunitas! Silakan baca [CONTRIBUTING.md](CONTRIBUTING.md) untuk guidelines.

### Development Setup

```bash
# Fork repository
git clone https://github.com/yourusername/websecguard.git

# Create feature branch
git checkout -b feature/amazing-feature

# Make changes and commit
git commit -m "Add amazing feature"

# Push to branch
git push origin feature/amazing-feature

# Create Pull Request
```

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.

## 🆘 Support

- 📧 Email: <support@websecguard.com>
- 💬 Discord: [WebSecGuard Community](https://discord.gg/websecguard)
- 📖 Documentation: [docs.websecguard.com](https://docs.websecguard.com)
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/websecguard/issues)

## 🙏 Acknowledgments

- [OWASP Foundation](https://owasp.org/) untuk security guidelines
- [Metasploit Framework](https://www.metasploit.com/) untuk inspiration
- [Burp Suite](https://portswigger.net/burp) untuk methodology reference
- [Nmap](https://nmap.org/) untuk network scanning techniques
