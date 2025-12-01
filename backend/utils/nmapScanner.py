import subprocess
import shutil
import logging
from pathlib import Path
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional

# Logger
logger = logging.getLogger("nmapScanner")
logger.setLevel(logging.INFO)
if not logger.hasHandlers():
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[%(asctime)s] [NMAP] %(message)s'))
    logger.addHandler(handler)

def _ensure_nmap_installed() -> None:
    if shutil.which("nmap") is None:
        logger.error("nmap not found in PATH")
        raise FileNotFoundError("nmap executable not found. Install nmap.")

def _build_port_arg(option: str, specific_ports: Optional[List[int]] = None) -> List[str]:
    if option == "top100": return ["--top-ports", "100"]
    if option == "top1000": return ["--top-ports", "1000"]
    if option == "all": return ["-p-"]
    if option == "specific":
        if not specific_ports:
            return ["--top-ports", "1000"]
        return ["-p", ",".join(str(p) for p in specific_ports)]
    return ["--top-ports", "1000"]

def run_nmap(
    target: str,
    ports_option: str = "top1000",
    specific_ports: Optional[List[int]] = None,
    show_os: bool = False,
    show_service: bool = True,
    extra_args: Optional[List[str]] = None,
    timeout: int = 360
) -> Dict[str, Any]:
    _ensure_nmap_installed()

    # FIX: HAPUS "--open" agar closed/filtered tetap tampil
    cmd = ["nmap", "-T4", "-Pn", "-n", "--max-retries", "1", "-oX", "-"] 
    
    cmd += _build_port_arg(ports_option, specific_ports)

    if show_service:
        cmd += ["-sV"] 
    
    if show_os:
        cmd += ["-O", "--osscan-limit"]
    
    if extra_args:
        cmd += extra_args

    cmd.append(target)
    logger.info(f"Running nmap: {' '.join(cmd)}")

    try:
        if ports_option == "all": timeout = 1800 
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"open_ports": [], "os": None, "raw_stderr": "Scan Timeout"}

    xml_out = proc.stdout
    if not xml_out:
        return {"open_ports": [], "os": None, "raw_stderr": proc.stderr.strip()}

    parsed = _parse_nmap_xml(xml_out, show_os=show_os, show_service=show_service)
    parsed["target"] = target
    return parsed

def _parse_nmap_xml(xml_str: str, show_os: bool = False, show_service: bool = True) -> Dict[str, Any]:
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return {"open_ports": [], "os": None}

    result: Dict[str, Any] = {"open_ports": [], "os": None}
    host = root.find("host")
    if host is None: return result

    ports = host.find("ports")
    if ports is not None:
        for port in ports.findall("port"):
            portid = port.get("portid")
            proto = port.get("protocol")
            state_el = port.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"
            
            svc = port.find("service")
            service_name = "unknown"
            product_name = ""
            version_num = ""
            
            if svc is not None:
                service_name = svc.get("name", "unknown")
                tunnel = svc.get("tunnel")
                if tunnel == "ssl":
                    if service_name == "http": service_name = "https"
                    else: service_name = f"{tunnel}/{service_name}"

                if show_service:
                    product_name = svc.get("product", "")
                    version_num = svc.get("version", "")

            # --- SERVICE-BASED RISK ASSESSMENT ---
            # Logika penilaian berdasarkan NAMA SERVICE, bukan nomor port
            risk = "Info"
            advice = ""
            svc_lower = service_name.lower()

            if state == "open":
                # 1. Critical Services (Database, Telnet, FTP unencrypted)
                if any(s in svc_lower for s in ['mysql', 'postgresql', 'redis', 'mongodb', 'mssql', 'oracle', 'telnet', 'ftp']):
                    risk = "Critical"
                    advice = f"Service '{service_name}' terekspos publik. Sangat berbahaya. Wajib Firewall/VPN."
                
                # 2. Medium Risk (HTTP, Proxy, Management)
                elif 'http' in svc_lower and 'https' not in svc_lower and int(portid) != 80:
                     risk = "Medium"
                     advice = "Service HTTP di port non-standar. Pastikan tidak ada info sensitif."
                elif int(portid) == 80:
                     risk = "Medium"
                     advice = "HTTP tidak terenkripsi. Redirect ke 443 (HTTPS)."
                
                # 3. Safe Services
                elif 'https' in svc_lower or 'ssl' in svc_lower:
                    risk = "Safe"
                    advice = "Layanan terenkripsi (Aman)."
                elif 'ssh' in svc_lower:
                    risk = "Info"
                    advice = "SSH Server. Pastikan menggunakan Key Authentication & Fail2Ban."
                else:
                    risk = "Info"
                    advice = f"Port {portid} terbuka untuk {service_name}. Verifikasi kebutuhan."
            
            elif state == "filtered":
                risk = "Safe"
                advice = "Port difilter oleh Firewall (Bagus)."
            elif state == "closed":
                risk = "Safe"
                advice = "Port tertutup."

            # Gabungkan product & version untuk kolom version
            full_version = f"{product_name} {version_num}".strip()

            result["open_ports"].append({
                "port": int(portid),
                "protocol": proto,
                "service": service_name,
                "version": full_version,
                "state": state,
                "risk": risk,
                "advice": advice
            })

    if show_os:
        os_el = host.find("os")
        if os_el is not None:
            osmatch = os_el.find("osmatch")
            if osmatch is not None:
                result["os"] = {
                    "name": osmatch.get("name"),
                    "accuracy": osmatch.get("accuracy")
                }

    return result