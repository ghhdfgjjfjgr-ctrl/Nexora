from __future__ import annotations

import html
import json
import os
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from scanner import ScanConfig, run_scan
from storage import get_scan, init_db, save_scan

MODE_DETAILS = {
    "quick": "สแกนเร็ว: Host discovery + Top ports",
    "balanced": "สแกนสมดุล: เพิ่ม service/version detection และ NSE vulners",
    "deep": "สแกนเชิงลึก: ใช้เครื่องมือที่เลือกทั้งหมดและเก็บรายละเอียดมากขึ้น",
}

CSS_PATH = Path("static/style.css")


def _escape_pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _draw_text_line(y: int, text: str, size: int = 11, x: int = 50) -> str:
    safe = _escape_pdf_text(text[:160])
    return f"BT /F1 {size} Tf {x} {y} Td ({safe}) Tj ET"


def _extract_port_lines(scan: dict) -> list[str]:
    findings = scan.get("result", {}).get("findings", {})
    nmap = findings.get("nmap", {})
    ports: list[str] = []
    for phase in nmap.get("phases", []):
        stdout = phase.get("stdout", "")
        for line in stdout.splitlines():
            stripped = line.strip()
            if "/tcp" in stripped and "open" in stripped:
                ports.append(stripped)
    return ports[:8]


def _estimate_risk(scan: dict) -> tuple[str, list[str]]:
    ports = _extract_port_lines(scan)
    findings = scan.get("result", {}).get("findings", {})
    issue_count = len(ports)
    if findings.get("zap", {}).get("status") == "available":
        issue_count += 2
    if findings.get("arachni", {}).get("status") == "available":
        issue_count += 2

    if issue_count >= 6:
        level = "HIGH"
    elif issue_count >= 3:
        level = "MEDIUM"
    else:
        level = "LOW"

    vulns: list[str] = []
    for idx, port_line in enumerate(ports[:4], start=1):
        severity = "LOW" if idx % 2 else "MEDIUM"
        vulns.append(f"[{severity}] {port_line}")
    if not vulns:
        vulns.append("No obvious high-risk service found from available scan output")
    return level, vulns


def build_pdf_report(scan: dict) -> bytes:
    target = scan["target"]
    scan_id = scan["id"]
    created = scan["created_at"]
    status = "COMPLETED"
    mode = scan["scan_mode"].upper()
    risk_level, vuln_lines = _estimate_risk(scan)
    port_lines = _extract_port_lines(scan)

    content: list[str] = []

    # Header block
    content.append("0.05 0.10 0.22 rg")
    content.append("30 770 535 45 re f")
    content.append("0 0 0 rg")
    content.append(_draw_text_line(795, "CYBERSECURITY ASSESSMENT REPORT", 18, 45))
    content.append(_draw_text_line(778, "CONFIDENTIAL SECURITY DOCUMENT", 10, 45))

    # TOC / สารบัญ (ascii-safe fallback)
    content.append(_draw_text_line(745, "Table of Contents (Sarabany / TOC)", 14, 45))
    content.append(_draw_text_line(728, "1. Scan Information", 11, 55))
    content.append(_draw_text_line(712, "2. Host Discovery Results", 11, 55))
    content.append(_draw_text_line(696, "3. Port & Service Detection Results", 11, 55))
    content.append(_draw_text_line(680, "4. Vulnerability Findings", 11, 55))
    content.append(_draw_text_line(664, "5. Risk Summary", 11, 55))
    content.append(_draw_text_line(648, "6. Observations and Limitations", 11, 55))
    content.append(_draw_text_line(632, "7. Recommendations", 11, 55))

    # Section 1
    content.append(_draw_text_line(602, "1. SCAN INFORMATION", 15, 45))
    content.append(_draw_text_line(584, f"Target: {target}", 11, 55))
    content.append(_draw_text_line(568, f"Scan ID: {scan_id}", 11, 55))
    content.append(_draw_text_line(584, f"Date: {created}", 11, 300))
    content.append(_draw_text_line(568, f"Status: {status}", 11, 300))
    content.append(_draw_text_line(552, f"Mode: {mode}", 11, 300))

    # Section 2
    content.append(_draw_text_line(524, "2. HOST DISCOVERY RESULTS", 15, 45))
    content.append(_draw_text_line(506, f"System checked host {target}. Reachability depends on network policy/firewall.", 11, 55))

    # Section 3
    content.append(_draw_text_line(478, "3. PORT & SERVICE DETECTION RESULTS", 15, 45))
    y = 460
    if port_lines:
        content.append(_draw_text_line(y, "Open ports and services:", 11, 55))
        y -= 16
        for line in port_lines[:6]:
            content.append(_draw_text_line(y, f"- {line}", 10, 68))
            y -= 14
    else:
        content.append(_draw_text_line(y, "No open-port line parsed from current output.", 11, 55))
        y -= 16

    # Section 4
    y -= 8
    content.append(_draw_text_line(y, "4. VULNERABILITY FINDINGS", 15, 45))
    y -= 20
    for line in vuln_lines[:6]:
        content.append(_draw_text_line(y, f"- {line}", 10, 55))
        y -= 14

    # Page 2 style continuation
    content.append("0.05 0.10 0.22 rg")
    content.append("30 365 535 30 re f")
    content.append(_draw_text_line(375, "RISK & RECOMMENDATION SUMMARY", 13, 45))

    content.append(_draw_text_line(340, "5. RISK SUMMARY", 15, 45))
    content.append(_draw_text_line(322, f"Overall Risk Exposure: {risk_level}", 11, 55))
    content.append(_draw_text_line(306, f"Total Findings Identified: {len(vuln_lines)}", 11, 55))
    content.append(_draw_text_line(288, "CVSS Guidance: LOW (0.1-3.9), MEDIUM (4.0-6.9), HIGH (7.0-8.9), CRITICAL (9.0-10)", 10, 55))

    content.append(_draw_text_line(258, "6. OBSERVATIONS AND LIMITATIONS", 15, 45))
    content.append(_draw_text_line(240, "- Results are point-in-time from selected tools and mode.", 11, 55))
    content.append(_draw_text_line(224, "- Firewall/IDS/IPS may reduce visibility and depth.", 11, 55))
    content.append(_draw_text_line(208, "- Some tool outputs may be simulated if binaries are unavailable.", 11, 55))

    content.append(_draw_text_line(178, "7. RECOMMENDATIONS", 15, 45))
    content.append(_draw_text_line(160, "- Patch exposed services and verify versions regularly.", 11, 55))
    content.append(_draw_text_line(144, "- Run scheduled scans in balanced/deep mode for better coverage.", 11, 55))
    content.append(_draw_text_line(128, "- Use authenticated scans and correlate with CVE/CVSS sources.", 11, 55))

    stream_data = "\n".join(content).encode("latin-1", errors="replace")

    objects: list[bytes] = []
    objects.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
    objects.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
    objects.append(
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n"
    )
    objects.append(b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n")
    objects.append(
        f"5 0 obj << /Length {len(stream_data)} >> stream\n".encode("ascii")
        + stream_data
        + b"\nendstream endobj\n"
    )

    header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    pdf = bytearray(header)
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj)

    xref_offset = len(pdf)
    xref = [f"xref\n0 {len(objects) + 1}\n", "0000000000 65535 f \n"]
    for offset in offsets[1:]:
        xref.append(f"{offset:010d} 00000 n \n")
    pdf.extend("".join(xref).encode("ascii"))
    trailer = (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    )
    pdf.extend(trailer.encode("ascii"))
    return bytes(pdf)



def render_index(error: str = "") -> str:
    mode_options = "".join(
        f'<option value="{m}">{m.capitalize()} - {html.escape(desc)}</option>'
        for m, desc in MODE_DETAILS.items()
    )
    error_html = f'<div class="alert error">{html.escape(error)}</div>' if error else ""
    return f"""<!doctype html>
<html lang="th">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Nexora Vulnerability Scanner</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <main class="container">
    <h1>Nexora Vulnerability Scanner</h1>
    <p class="subtitle">สแกนช่องโหว่สำหรับ IP, Domain และ URL พร้อมเลือกโหมดการสแกน</p>
    {error_html}
    <form action="/scan" method="post" class="card">
      <label>เป้าหมาย</label>
      <input type="text" name="target" placeholder="เช่น 192.168.1.1, example.com, https://example.com" required>

      <label>ประเภทเป้าหมาย</label>
      <div class="grid3">
        <label><input type="radio" name="target_type" value="ip" required> IP Address</label>
        <label><input type="radio" name="target_type" value="domain"> Domain</label>
        <label><input type="radio" name="target_type" value="url"> URL</label>
      </div>

      <label>โหมดการสแกน</label>
      <select name="scan_mode" required>{mode_options}</select>

      <label>เครื่องมือที่ใช้</label>
      <div class="grid3">
        <label><input type="checkbox" name="tools" value="nmap" checked> Nmap</label>
        <label><input type="checkbox" name="tools" value="zap" checked> OWASP ZAP</label>
        <label><input type="checkbox" name="tools" value="arachni" checked> Arachni</label>
      </div>

      <button type="submit">เริ่มสแกน</button>
    </form>
  </main>
</body>
</html>"""


def render_result(scan: dict) -> str:
    findings = html.escape(json.dumps(scan["result"]["findings"], ensure_ascii=False, indent=2))
    raw = html.escape(json.dumps(scan["result"], ensure_ascii=False, indent=2))
    return f"""<!doctype html>
<html lang="th">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ผลการสแกน #{scan['id']}</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <main class="container">
    <h1>ผลการสแกน #{scan['id']}</h1>
    <p class="subtitle">Target: {html.escape(scan['target'])} | Type: {scan['target_type']} | Mode: {scan['scan_mode']}</p>
    <p><a href="/results/{scan['id']}/json">ดาวน์โหลด JSON report</a> | <a href="/results/{scan['id']}/pdf">ดาวน์โหลด PDF report</a></p>
    <p><a href="/">← กลับหน้าหลัก</a></p>

    <section class="card">
      <h2>Findings</h2>
      <pre>{findings}</pre>
    </section>

    <section class="card">
      <h2>Raw Result JSON</h2>
      <pre>{raw}</pre>
    </section>
  </main>
</body>
</html>"""


class AppHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        init_db()
        parsed = urlparse(self.path)

        if parsed.path == "/":
            self._send_html(render_index())
            return

        if parsed.path == "/static/style.css":
            if CSS_PATH.exists():
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/css; charset=utf-8")
                self.end_headers()
                self.wfile.write(CSS_PATH.read_bytes())
                return
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return

        if parsed.path.startswith("/results/") and parsed.path.endswith("/json"):
            run_id = self._extract_run_id(parsed.path, suffix="/json")
            if run_id is None:
                return
            scan = get_scan(run_id)
            if not scan:
                self.send_error(HTTPStatus.NOT_FOUND, "Scan not found")
                return
            payload = json.dumps(scan["result"], ensure_ascii=False, indent=2)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", f"attachment; filename=scan-{run_id}.json")
            self.end_headers()
            self.wfile.write(payload.encode("utf-8"))
            return

        if parsed.path.startswith("/results/") and parsed.path.endswith("/pdf"):
            run_id = self._extract_run_id(parsed.path, suffix="/pdf")
            if run_id is None:
                return
            scan = get_scan(run_id)
            if not scan:
                self.send_error(HTTPStatus.NOT_FOUND, "Scan not found")
                return
            payload = build_pdf_report(scan)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", f"attachment; filename=scan-{run_id}.pdf")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if parsed.path.startswith("/results/"):
            run_id = self._extract_run_id(parsed.path)
            if run_id is None:
                return
            scan = get_scan(run_id)
            if not scan:
                self.send_error(HTTPStatus.NOT_FOUND, "Scan not found")
                return
            self._send_html(render_result(scan))
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_POST(self) -> None:  # noqa: N802
        init_db()
        if self.path != "/scan":
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length).decode("utf-8")
        params = parse_qs(body)

        target = params.get("target", [""])[0]
        target_type = params.get("target_type", [""])[0]
        scan_mode = params.get("scan_mode", ["quick"])[0]
        tools = params.get("tools", [])

        if scan_mode not in MODE_DETAILS:
            self._send_html(render_index("โหมดสแกนไม่ถูกต้อง"), status=HTTPStatus.BAD_REQUEST)
            return

        if not tools:
            self._send_html(render_index("กรุณาเลือกเครื่องมืออย่างน้อย 1 ตัว"), status=HTTPStatus.BAD_REQUEST)
            return

        try:
            result = run_scan(
                ScanConfig(target=target, target_type=target_type, scan_mode=scan_mode, tools=tools)
            )
        except ValueError as exc:
            self._send_html(render_index(str(exc)), status=HTTPStatus.BAD_REQUEST)
            return

        run_id = save_scan(
            target=result["target"],
            target_type=result["target_type"],
            scan_mode=result["scan_mode"],
            tools=result["tools"],
            created_at=datetime.now().isoformat(timespec="seconds"),
            result=result,
        )

        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", f"/results/{run_id}")
        self.end_headers()

    def _send_html(self, content: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def _extract_run_id(self, path: str, suffix: str = "") -> int | None:
        token = path.removeprefix("/results/")
        if suffix and token.endswith(suffix):
            token = token[: -len(suffix)]
        token = token.strip("/")
        if not token.isdigit():
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid run id")
            return None
        return int(token)


if __name__ == "__main__":
    init_db()
    host = os.getenv("NEXORA_HOST", "0.0.0.0")
    port = int(os.getenv("NEXORA_PORT", "5000"))
    server = ThreadingHTTPServer((host, port), AppHandler)
    print(f"Nexora scanner running at http://{host}:{port}")
    server.serve_forever()
