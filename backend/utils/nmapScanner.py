import subprocess
import shutil
import logging
import platform
import os
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
    nmap_path = shutil.which("nmap")
    
    # Coba path default Windows jika tidak ketemu di PATH
    if nmap_path is None and platform.system() == "Windows":
        potential_paths = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe"
        ]
        for p in potential_paths:
            if os.path.exists(p):
                nmap_path = p
                # Tambahkan ke PATH sementara agar subprocess bisa memanggilnya
                os.environ["PATH"] += os.pathsep + os.path.dirname(p)
                break
    
    if nmap_path is None:
        logger.error("nmap not found in PATH")
        raise FileNotFoundError("nmap executable not found. Install nmap and add to PATH.")

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
    timeout: int = 360 # DEFAULT BARU: 6 Menit (360 detik)
) -> Dict[str, Any]:
    _ensure_nmap_installed()

    # --- KONFIGURASI NMAP ---
    # -T4: Cepat
    # -Pn: Bypass Ping (Wajib untuk WAF)
    # -n: No DNS resolution (Hemat waktu)
    # --max-retries 1: Jangan buang waktu mengulang paket yang didrop
    # --host-timeout 5m: Minta Nmap menyerah pada host jika > 5 menit
    cmd = ["nmap", "-T3", "-Pn", "-n", "--max-retries", "1", "--host-timeout", "5m", "-oX", "-"] 
    
    cmd += _build_port_arg(ports_option, specific_ports)

    if show_service: cmd += ["-sV", "--version-intensity", "5"] # Intensity 5 (Medium) lebih cepat dari 7
    if show_os: cmd += ["-O", "--osscan-limit"]
    if extra_args: cmd += extra_args

    cmd.append(target)
    logger.info(f"Running nmap: {' '.join(cmd)}")

    try:
        # Jalankan subprocess dengan Timeout Keras (Hard Limit) dari Python
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        # --- SKENARIO GAGAL SCAN ---
        error_msg = (
            f"TIMEOUT: Nmap dihentikan paksa setelah {timeout} detik (6 menit). "
            "Kemungkinan penyebab: 1) WAF memblokir/membuang paket (Drop), "
            "2) Koneksi server sangat lambat, atau 3) Terlalu banyak port yang discan."
        )
        logger.error(error_msg)
        return {
            "open_ports": [], 
            "os": None, 
            "raw_stderr": error_msg,
            "scan_status": "timeout"
        }

    xml_out = proc.stdout
    if not xml_out:
        logger.warning(f"nmap no XML output; stderr: {proc.stderr.strip()}")
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
            svc_name = "unknown"
            version_info = None
            
            if svc is not None:
                svc_name = svc.get("name", "unknown")
                tunnel = svc.get("tunnel")
                if tunnel == "ssl":
                    if svc_name == "http": svc_name = "https"
                    else: svc_name = f"{tunnel}/{svc_name}"

                if show_service:
                    product = svc.get("product")
                    version = svc.get("version")
                    parts = []
                    if product: parts.append(product)
                    if version: parts.append(version)
                    version_info = " ".join(parts) if parts else None

            result["open_ports"].append({
                "port": int(portid) if portid and portid.isdigit() else portid,
                "protocol": proto,
                "service": svc_name if show_service else None,
                "version": version_info,
                "state": state
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