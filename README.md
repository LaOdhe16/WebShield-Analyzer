# WebShield Analyzer — Enterprise Security & OSINT Engine

WebShield Analyzer is an advanced Open-Source Intelligence (OSINT) and web vulnerability scanner built for cybersecurity professionals, Bug Hunters, and System Administrators. This tool is designed to provide full visibility into web infrastructure, domain reputation, and compliance with modern HTTP security standards in just a single click.

## 🚀 Key Features

- **Vulnerability Mitigation**: Inspects the implementation of HTTP security policies (HSTS, CSP, X-Frame-Options, etc.) and provides direct mitigation guides based on OWASP/MDN standards.
- **Threat & Malware Intelligence**: Integrates directly with the VirusTotal API to detect malware reputation and phishing indicators in real-time.
- **Advanced OSINT Discovery**:
  - Hidden subdomain tracking via Certificate Transparency Logs (crt.sh).
  - WHOIS Data extraction (Registrar & Domain creation history).
  - Historical website footprint analysis via Wayback Machine (Archive.org).
- **Network & Geo-Intelligence**:
  - Tracks the server's real IP address, geographical location (City/Country), ISP, and ASN.
  - Blazing-fast asynchronous Port Scanner (checks FTP, SSH, HTTP, Database ports).
  - CMS & Tech Stack Detection (detects WordPress, underlying frameworks, etc.).
- **DNS Email Security**: Verifies SPF and DMARC records to identify vulnerabilities related to Email Spoofing.
- **Sensitive Information Disclosure**: Hunts for publicly exposed sensitive endpoints or files such as `/.env`, `/.git/config`, and `/robots.txt`.

## 🛠️ Technology Stack & Integrations

This application is built using a modern, lightweight, yet powerful architecture:

### ⚙️ Backend (Core Engine)
- **Python 3.10+**: Core programming language.
- **Flask**: Micro web framework for API routing and template rendering.
- **Concurrent Futures**: Utilized for parallel port scanning (Multi-threading) to ensure maximum scanning performance.
- **Core Libraries**: `requests`, `python-whois`, `dnspython`, `beautifulsoup4`.

### 🎨 Frontend (UI/UX)
- **Tailwind CSS**: Utility-first CSS framework for a clean, responsive, and highly customizable design.
- **Jinja2**: Flask's templating engine for structuring multi-page layouts (`base`, `home`, `scanner`, `about`).
- **Enterprise-Grade UI**: Professional interface featuring a monochrome color palette (Zinc/Black), backdrop-blur effects (glassmorphism), and pure **SVG Vector Icons** (no emojis) to deliver a premium, enterprise-level cybersecurity tool experience.
- **Vanilla JavaScript**: Handles asynchronous interactions (AJAX/Fetch API) with the backend to ensure a seamless scanning process without page reloads.

### 🔌 External API Integrations
- **VirusTotal API v3**: Analyzes URLs against dozens of global antivirus engines.
- **IP-API**: Fetches network intelligence and geographical IP data.
- **crt.sh**: Certificate transparency log search API for passive subdomain OSINT.
- **Wayback Machine API**: Accesses historical internet archives.

---

## 📦 Installation & Usage Guide

You can run this tool in a local environment (Manual) or an isolated containerized environment (Docker).

### Option 1: Running via Docker (Highly Recommended)
This project fully supports containerization. You don't need to manually install Python or any libraries. Just ensure Docker Desktop/Engine is installed on your machine.

**Method A: Using Docker Compose (One-Click Setup)**
```bash
docker-compose up --build
```

**Method B: Using Standard Docker CLI (MobSF/Security Tools Style)**
```bash
docker build -t webshield-analyzer:latest .
docker run -it --rm -p 5000:5000 webshield-analyzer:latest
```

### Option 2: Manual Installation (Local / Native)
If you wish to further develop the application natively on your OS:

1. Clone the Repository:
   ```bash
   git clone https://github.com/LaOdhe16/WebShield-Analyzer
   cd webshield-analyzer
   ```
2. Setup a Virtual Environment:
   ```bash
   python -m venv venv

   # For Linux/Mac:
   source venv/bin/activate  

   # For Windows:
   venv\Scripts\activate
   ```
   
3. Install Dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   
4. Configure API Keys:
   Open the app.py file, locate the VT_API_KEY variable, and insert your VirusTotal API Key (you can get one for free by registering on VirusTotal).
   
5. Run the Aplication:
   ```bash
   python app.py
   ```
   Access the web interface at: http://localhost:5000

## ⚖️ Legal Disclaimer
This tool is developed purely for Educational and Defensive Security purposes. The active scanning performed by this tool is very lightweight, but authorization is still strictly required.

The user agrees to use this software only on network/web systems they own or have explicit written authorization to scan. The developer assumes no liability and is not responsible for any misuse, damage, loss, or illegal activities conducted using this tool.

