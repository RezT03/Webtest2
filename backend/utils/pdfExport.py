from sqlite3 import Cursor
from fpdf import FPDF
import datetime
import re
import json, sys

def export_to_pdf(results, filename='hasil_uji.pdf', user_id=None, cursor=None):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(200, 10, 'Laporan Pengujian Keamanan', ln=True, align='C')
    pdf.set_font('Arial', '', 12)

    if user_id is not None and cursor is not None:
        cursor.execute("SELECT * FROM test_results WHERE user_id = ? AND test_type = 'DoS'", (user_id,))
        dos_results = cursor.fetchall()
    else:
        dos_results = []

    if dos_results:
        pdf.add_page()
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(200, 10, 'Analisis Ketahanan DoS', ln=True)
        for r in dos_results:
            try:
                match = re.search(r'(\d+(\.\d+)?)(KB|MB)', r['request_payload'])
                size_kb = float(match.group(1)) * (1024 if match.group(3) == 'MB' else 1)
                users = 3000
                capacity = float(size_kb * users / 1024)
                pdf.set_font('Arial', '', 12)
                pdf.multi_cell(0, 10, f"Jika halaman {r['target_url']} memuat {match.group(0)} per pengguna dan jumlah pengguna aktif {users}, maka estimasi total load: {capacity:.2f} MB.")
                pdf.multi_cell(0, 10, f"Server mengalami down pada {r['result']} request bersamaan. Pertimbangkan optimasi ukuran data, CDN, atau distribusi beban.")
            except:
                pdf.multi_cell(0, 10, "Data tidak dapat dianalisis untuk estimasi beban pengguna.")

    for r in results:
        pdf.ln(10)
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(200, 10, f"Jenis Uji: {r['test_type']}", ln=True)
        pdf.set_font('Arial', '', 11)
        pdf.multi_cell(0, 10, f"Target: {r['target_url']}\nHasil: {r['result']}\nRingkasan: {r['summary']}")

    pdf.output(filename)

# Contoh pemanggilan (jangan letakkan di dalam file jika hanya ingin sebagai modul)
# results = [
#     { "test_type": "Tech Detection", "target_url": target, "result": "\n".join(tech), "summary": "Teknologi yang digunakan" },
#     ...
# ]
# export_to_pdf(results, filename=pdf_path)