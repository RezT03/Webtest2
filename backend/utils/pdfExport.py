import json
import sys
import os
import logging
import traceback
from datetime import datetime

logging.basicConfig(stream=sys.stderr, level=logging.INFO, format='[PDFExport] %(message)s')
logger = logging.getLogger("pdfExport")

def safe_log(msg):
    logger.info(str(msg))

# --- FUNGSI RENDER TEMPLATE ---
def render_html_from_template(scan_result):
    try:
        from jinja2 import Environment, FileSystemLoader
    except ImportError:
        safe_log("CRITICAL: Library 'jinja2' not found.")
        return None

    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # List kemungkinan lokasi template
    possible_paths = [
        os.path.join(current_dir, "templates"),
        current_dir,
        os.path.join(os.path.dirname(current_dir), "templates")
    ]
    
    template_dir = None
    for p in possible_paths:
        if os.path.exists(os.path.join(p, "report.html")):
            template_dir = p
            safe_log(f"Template found in: {template_dir}")
            break
    
    if not template_dir:
        safe_log(f"ERROR: report.html not found in {possible_paths}")
        return None

    try:
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template("report.html")
        
        # Data Cleaning (Agar template tidak crash jika data kosong)
        def get_val(data, key, default=None):
            if isinstance(data, dict):
                return data.get(key, default)
            return default

        security_score = get_val(scan_result, 'security_score', {})
        
        context = {
            'target_url': get_val(scan_result, 'url', 'Unknown Target'),
            'scan_date': datetime.now().strftime('%d-%m-%Y %H:%M:%S'),
            'security_score': {
                'final_score': get_val(security_score, 'final_score', 'N/A'),
                'cve_score': get_val(security_score, 'cve_score', '-'),
                'zap_score': get_val(security_score, 'zap_score', '-'),
                'details': get_val(security_score, 'details', [])
            },
            'impact_analysis': get_val(scan_result, 'impact_analysis', {'summary': '-', 'label': 'Info'}),
            'tech': get_val(scan_result, 'tech', []),
            'cves': get_val(scan_result, 'cves', []),
            'zap_alerts': get_val(scan_result, 'zap_alerts', []),
            'xss_results': get_val(scan_result, 'xss_results', []),
            'sqli_results': get_val(scan_result, 'sqli_results', []),
            'ssl_result': get_val(scan_result, 'ssl_result'),
            'nmap_result': get_val(scan_result, 'nmap_result'),
            'ratelimit_result': get_val(scan_result, 'ratelimit_result'),
            'stats': {
                'tech_count': len(get_val(scan_result, 'tech', []) or []),
                'cve_count': len(get_val(scan_result, 'cves', []) or []),
                'zap_count': len(get_val(scan_result, 'zap_alerts', []) or [])
            }
        }
        
        return template.render(context)
    except Exception as e:
        safe_log(f"Template Render Error: {e}")
        safe_log(traceback.format_exc())
        return None

# --- FUNGSI GENERATE PDF ---
def generate_pdf(html_content, output_path):
    try:
        from xhtml2pdf import pisa
    except ImportError:
        safe_log("CRITICAL: Library 'xhtml2pdf' not found.")
        return False, "xhtml2pdf not installed"

    try:
        # Pastikan folder tujuan ada
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, "wb") as result_file:
            pisa_status = pisa.CreatePDF(src=html_content, dest=result_file)
        
        if pisa_status.err:
            return False, f"xhtml2pdf error code: {pisa_status.err}"
        return True, "Success"
    except Exception as e:
        return False, str(e)

# --- MAIN BLOCK ---
if __name__ == "__main__":
    try:
        # 1. Baca JSON Input
        input_str = sys.stdin.read()
        if not input_str:
            print(json.dumps({"status": "error", "error": "No input data received"}))
            sys.exit(0)
            
        try:
            data_wrapper = json.loads(input_str)
            scan_result = data_wrapper.get('result', data_wrapper)
        except json.JSONDecodeError:
            print(json.dumps({"status": "error", "error": "Invalid JSON format"}))
            sys.exit(0)

        current_dir = os.path.dirname(os.path.abspath(__file__)) # backend/utils
        backend_dir = os.path.dirname(current_dir) # backend
        root_dir = os.path.dirname(backend_dir) # root project
        
        # Target: root/frontend/public/downloads
        public_dir = os.path.join(root_dir, 'frontend', 'public')
        
        # Fallback jika folder frontend tidak ada (misal struktur flat)
        if not os.path.exists(public_dir):
            safe_log(f"Frontend public dir not found at {public_dir}, checking local public...")
            public_dir = os.path.join(backend_dir, 'public')
            if not os.path.exists(public_dir):
                public_dir = os.path.join(os.getcwd(), 'public')

        download_dir = os.path.join(public_dir, 'downloads')
        
        # Buat nama file unik
        filename = f"Security_Report_{int(datetime.now().timestamp())}.pdf"
        full_path = os.path.join(download_dir, filename)
        
        safe_log(f"Writing PDF to: {full_path}")

        # 3. Proses Render
        html = render_html_from_template(scan_result)
        if not html:
            print(json.dumps({"status": "error", "error": "Template rendering failed (check logs)"}))
            sys.exit(0)

        success, msg = generate_pdf(html, full_path)

        # 4. Kirim Hasil ke Node.js
        if success and os.path.exists(full_path):
            response = {
                "status": "success",
                # URL relatif yang akan diakses browser (sesuai app.js static serve)
                "download_url": f"/downloads/{filename}", 
                "message": "PDF Created"
            }
            print(json.dumps(response))
        else:
            print(json.dumps({"status": "error", "error": f"PDF Generation Failed: {msg}"}))

    except Exception as e:
        safe_log(traceback.format_exc())
        print(json.dumps({"status": "error", "error": f"Script Crash: {str(e)}"}))