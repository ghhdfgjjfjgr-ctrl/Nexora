# Nexora Vulnerability Scanner

เว็บแอปสแกนช่องโหว่ที่รองรับ **IP / Domain / URL** พร้อมโหมดการสแกนหลายแบบ และการส่งออกผลลัพธ์เป็น JSON

## ความสามารถหลัก
- รองรับเป้าหมาย 3 แบบ: IP, Domain, URL
- เลือกโหมดสแกน: `quick`, `balanced`, `deep`
- เลือกเครื่องมือ: `Nmap`, `OWASP ZAP`, `Arachni`
- เก็บผลลัพธ์ลง SQLite (`scan_results.db`)
- เปิดดูผลผ่านหน้าเว็บและดาวน์โหลด JSON/PDF report
- ดาวน์โหลดผลลัพธ์ได้ทั้ง JSON และ PDF report (รูปแบบรายงานหลายหัวข้อพร้อมสารบัญ)

## โหมดสแกน
- **quick**: เน้นความเร็ว (host discovery + ports พื้นฐาน)
- **balanced**: เพิ่มการตรวจ service/version และ NSE `vulners`
- **deep**: สแกนเชิงลึกมากขึ้น พร้อมเครื่องมือทั้งหมดที่เลือก

## รันแบบ Local
```bash
python app.py
```

จากนั้นเปิด `http://localhost:5000`

## ติดตั้งบน Kali Linux (Raspberry Pi) ด้วย GitHub + Install Script

> เหมาะสำหรับ deploy แบบ service อัตโนมัติผ่าน `systemd`

1) โคลน repo (หรือใช้ repo ของคุณ)
```bash
git clone <YOUR_GITHUB_REPO_URL>
cd Nexora
```

2) รันสคริปต์ติดตั้ง (ต้องใช้ sudo)
```bash
sudo bash scripts/install_kali_rpi.sh \
  --repo <YOUR_GITHUB_REPO_URL> \
  --branch main \
  --dir /opt/nexora-scanner \
  --user www-data \
  --group www-data \
  --host 0.0.0.0 \
  --port 5000
```

3) ตรวจสอบสถานะ service
```bash
systemctl status nexora-scanner
```

4) เปิดใช้งานจากเครื่องอื่นในวง LAN
```text
http://<RASPBERRY_PI_IP>:5000
```

### อัปเดตเวอร์ชันใหม่จาก GitHub
รัน install script ซ้ำได้เลย ระบบจะ `git fetch/reset` และรีสตาร์ต service อัตโนมัติ
```bash
sudo bash scripts/install_kali_rpi.sh --repo <YOUR_GITHUB_REPO_URL> --branch main
```

## ติดตั้ง “บนเครื่องนี้เลย” แบบครบ (GitHub repo + install script)

หากอยู่บน Kali Linux (Raspberry Pi) แล้วต้องการติดตั้งให้ครบในคำสั่งเดียว:

```bash
# 1) clone repo installer มาก่อน
git clone <YOUR_GITHUB_REPO_URL>
cd Nexora

# 2) bootstrap + install service ครบ
sudo bash scripts/full_setup_kali_rpi.sh \
  --repo <YOUR_GITHUB_REPO_URL> \
  --branch main \
  --dir /opt/nexora-scanner \
  --user www-data \
  --group www-data \
  --host 0.0.0.0 \
  --port 5000
```

เช็กผลหลังติดตั้ง:
```bash
systemctl status nexora-scanner
curl -sS http://127.0.0.1:5000 | head
```

ถอนการติดตั้ง:
```bash
sudo bash scripts/uninstall_kali_rpi.sh --remove-data
```

## หมายเหตุ
- หากเครื่องไม่มี `nmap`, `zap.sh`, `arachni` ระบบจะบันทึกสถานะ `skipped/simulated` พร้อมคำแนะนำ
- ใช้งานเฉพาะกับเป้าหมายที่ได้รับอนุญาตเท่านั้น
- PDF เวอร์ชันปัจจุบันเป็นรายงานแบบโครงสร้าง (TOC + summary + findings) และสามารถต่อยอดฝังฟอนต์ไทย (เช่น TH Sarabun) ได้เมื่อมีไฟล์ฟอนต์ในระบบ
