-- Tabel pengguna
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Hasil pengujian umum (XSS, SQLi, DoS, misconfig, dll)
CREATE TABLE test_results (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  test_type ENUM('SQLI', 'XSS', 'DoS', 'ServerMisconfig', 'CVE', 'scan-all'),
  target_url TEXT,
  request_payload TEXT,
  result TEXT,
  summary TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- CVE terkait teknologi/software yang terdeteksi
CREATE TABLE tech_cve_results (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  target_url TEXT,
  software TEXT,
  version TEXT,
  cve_id VARCHAR(50),
  description TEXT,
  solution TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Statistik DoS tambahan jika perlu digunakan (opsional)
CREATE TABLE dos_stats (
  id INT AUTO_INCREMENT PRIMARY KEY,
  result_id INT,
  requests_sent INT,
  server_response_time FLOAT,
  peak_load FLOAT,
  FOREIGN KEY (result_id) REFERENCES test_results(id) ON DELETE CASCADE
);