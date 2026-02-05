from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse


@dataclass
class ScanConfig:
    target: str
    target_type: str
    scan_mode: str
    tools: list[str]


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)


def validate_target(target: str, target_type: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("กรุณาระบุเป้าหมาย")

    if target_type == "ip":
        ipaddress.ip_address(target)
        return target

    if target_type == "domain":
        if not DOMAIN_PATTERN.match(target):
            raise ValueError("โดเมนไม่ถูกต้อง")
        return target.lower()

    if target_type == "url":
        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("URL ต้องขึ้นต้นด้วย http:// หรือ https://")
        return target

    raise ValueError("ประเภทเป้าหมายไม่ถูกต้อง")


def run_scan(config: ScanConfig) -> dict:
    started_at = datetime.now(timezone.utc).isoformat()
    normalized_target = validate_target(config.target, config.target_type)
    findings: dict[str, dict] = {}

    if "nmap" in config.tools:
        findings["nmap"] = run_nmap(normalized_target, config.target_type, config.scan_mode)
    if "zap" in config.tools:
        findings["zap"] = run_zap(normalized_target, config.target_type, config.scan_mode)
    if "arachni" in config.tools:
        findings["arachni"] = run_arachni(normalized_target, config.target_type, config.scan_mode)

    return {
        "target": normalized_target,
        "target_type": config.target_type,
        "scan_mode": config.scan_mode,
        "tools": config.tools,
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }


def run_nmap(target: str, target_type: str, scan_mode: str) -> dict:
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        return {
            "status": "skipped",
            "reason": "ไม่พบ nmap ในระบบ",
            "hint": "ติดตั้ง nmap ก่อนใช้งานจริง หรือรันทดสอบใน Kali Linux",
        }

    target_for_nmap = target
    if target_type == "url":
        host = urlparse(target).hostname
        if not host:
            return {"status": "error", "reason": "ไม่สามารถแยก host จาก URL"}
        target_for_nmap = host

    phases = []
    phase_commands = {
        "host_discovery": [nmap_bin, "-sn", target_for_nmap],
        "port_service_detection": [nmap_bin, "-sV", "--top-ports", "100", target_for_nmap],
    }

    if scan_mode in {"balanced", "deep"}:
        phase_commands["vulnerability_nse"] = [
            nmap_bin,
            "-sV",
            "--script",
            "vulners",
            target_for_nmap,
        ]

    for phase, cmd in phase_commands.items():
        output = _run_command(cmd)
        phases.append({"phase": phase, **output})

    return {
        "status": "completed",
        "target_resolved": resolve_target(target_for_nmap),
        "phases": phases,
    }


def run_zap(target: str, target_type: str, scan_mode: str) -> dict:
    if target_type != "url":
        return {
            "status": "skipped",
            "reason": "OWASP ZAP ใช้กับ URL เท่านั้น",
        }

    zap_bin = shutil.which("zap.sh") or shutil.which("zaproxy")
    if not zap_bin:
        return {
            "status": "simulated",
            "reason": "ไม่พบ OWASP ZAP ในระบบ",
            "simulated_checks": [
                "Passive scan (headers, cookies, TLS)",
                "Spider + Active scan ตามโหมดที่เลือก",
            ],
            "note": f"โหมด {scan_mode}: แนะนำรันผ่าน ZAP API เพื่อเก็บรายงานจริง",
        }

    return {
        "status": "available",
        "binary": zap_bin,
        "note": "พบ ZAP ในระบบ แต่ตัวอย่างนี้ไม่ได้เรียก active scan จริงเพื่อความปลอดภัย",
    }


def run_arachni(target: str, target_type: str, scan_mode: str) -> dict:
    if target_type != "url":
        return {
            "status": "skipped",
            "reason": "Arachni ใช้กับ URL เท่านั้น",
        }

    arachni_bin = shutil.which("arachni")
    if not arachni_bin:
        return {
            "status": "simulated",
            "reason": "ไม่พบ Arachni ในระบบ",
            "simulated_checks": ["XSS", "SQL Injection"],
            "note": "สามารถต่อยอดด้วย arachni_reporter เพื่อ export JSON",
        }

    return {
        "status": "available",
        "binary": arachni_bin,
        "note": "พบ Arachni ในระบบ แต่ปิดการยิงจริงในเดโม",
    }


def _run_command(cmd: list[str]) -> dict:
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        return {
            "command": " ".join(cmd),
            "return_code": completed.returncode,
            "stdout": completed.stdout[-6000:],
            "stderr": completed.stderr[-3000:],
        }
    except subprocess.TimeoutExpired:
        return {
            "command": " ".join(cmd),
            "return_code": -1,
            "stdout": "",
            "stderr": "คำสั่งหมดเวลา (timeout)",
        }


def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except OSError:
        return "unresolved"
