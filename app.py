from flask import Flask, request, jsonify, render_template
import requests
import re
import ssl
import socket
import dns.resolver
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
import concurrent.futures

app = Flask(__name__)

# API KEY VirusTotal 
VT_API_KEY = "Salin_API_KEY"

def analyze_url_patterns(url):
    suspicions = []
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url): suspicions.append("URL menggunakan IP Address (Indikasi Phishing/Bypass).")
    if len(url) > 75: suspicions.append("URL terlalu panjang (Mungkin menyembunyikan payload).")
    if url.count('.') > 4: suspicions.append("Terlalu banyak subdomain.")
    return suspicions

def check_security_headers(url):
    headers_to_check = {
        'Strict-Transport-Security': {
            'desc': 'Mencegah serangan Man-in-the-Middle dan downgrade HTTP.',
            'mitigasi': 'Tambahkan header HSTS pada server. Contoh (Nginx): add_header Strict-Transport-Security "max-age=31536000" always;',
            'doc': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'
        },
        'Content-Security-Policy': {
            'desc': 'Mencegah eksekusi script berbahaya (Cross-Site Scripting / XSS).',
            'mitigasi': 'Terapkan kebijakan CSP yang ketat. Contoh: Content-Security-Policy: default-src \'self\';',
            'doc': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'
        },
        'X-Frame-Options': {
            'desc': 'Mencegah website ditampilkan di dalam frame (serangan Clickjacking).',
            'mitigasi': 'Tambahkan header X-Frame-Options: DENY atau SAMEORIGIN di konfigurasi server.',
            'doc': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'
        }
    }
    
    results = {}
    server_info = []
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        for header, info in headers_to_check.items():
            if header in headers:
                results[header] = {"status": "Aman", "desc": info['desc'], "mitigasi": "Konfigurasi sudah baik.", "doc": info['doc']}
            else:
                results[header] = {"status": "Rentang", "desc": info['desc'], "mitigasi": info['mitigasi'], "doc": info['doc']}
        
        if 'Server' in headers: server_info.append(f"Server: {headers['Server']}")
        if 'X-Powered-By' in headers: server_info.append(f"Framework: {headers['X-Powered-By']}")
        return results, server_info, True
    except: return {}, [], False

def check_ssl(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expire_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_date - datetime.utcnow()).days
                return {"status": "Valid", "info": f"Sisa {days_left} hari (Kedaluwarsa: {expire_date.strftime('%Y-%m-%d')})"}
    except: return {"status": "Tidak Valid", "info": "Sertifikat SSL bermasalah atau HTTPS tidak tersedia."}

def check_virustotal(url):
    try:
        vt_url = "https://www.virustotal.com/api/v3/urls"
        response = requests.post(vt_url, data={"url": url}, headers={"accept": "application/json", "x-apikey": VT_API_KEY, "content-type": "application/x-www-form-urlencoded"})
        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            report_res = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers={"x-apikey": VT_API_KEY})
            stats = report_res.json()['data']['attributes']['stats']
            malicious, suspicious = stats.get('malicious', 0), stats.get('suspicious', 0)
            if malicious > 0 or suspicious > 0: 
                return {"status": "Bahaya", "data": f"Ditandai Berbahaya: {malicious}, Mencurigakan: {suspicious} vendor."}
            return {"status": "Bersih", "data": "Aman dari database Malware/Phishing."}
        elif response.status_code == 401: return {"status": "Error", "data": "API Key VirusTotal belum dikonfigurasi / salah."}
        else: return {"status": "Error", "data": f"Gagal menghubungi VirusTotal."}
    except Exception as e: return {"status": "Error", "data": "Koneksi ke VirusTotal gagal."}

def get_ip_geo(domain):
    try:
        ip = socket.gethostbyname(domain)
        res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,as", timeout=5).json()
        if res['status'] == 'success':
            return {"ip": ip, "country": res['country'], "city": res['city'], "isp": res['isp'], "asn": res['as']}
        return {"ip": ip, "error": "Data Geo gagal ditarik."}
    except: return {"error": "Gagal resolve IP."}

def get_subdomains(domain):
    try:
        base_domain = domain.replace('www.', '')
        res = requests.get(f"https://crt.sh/?q=%.{base_domain}&output=json", timeout=10)
        if res.status_code == 200:
            subdomains = list(set([entry['name_value'].lower() for entry in res.json()]))
            subdomains = [sub for sub in subdomains if '*' not in sub][:10] 
            return subdomains if subdomains else ["Tidak ada subdomain ditemukan."]
        return ["crt.sh tidak merespons."]
    except: return ["Timeout saat mencari subdomain."]

def check_dns_security(domain):
    base_domain = domain.replace('www.', '')
    records = {"SPF": "Hilang (Rentang Spoofing)", "DMARC": "Hilang (Rentang Spoofing)"}
    try:
        for r in dns.resolver.resolve(base_domain, 'TXT'):
            if "v=spf1" in r.to_text().lower(): records["SPF"] = "Aman (Terkonfigurasi)"
        for r in dns.resolver.resolve(f"_dmarc.{base_domain}", 'TXT'):
            if "v=dmarc1" in r.to_text().lower(): records["DMARC"] = "Aman (Terkonfigurasi)"
    except: pass
    return records

def scan_port(domain, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((domain, port)) == 0: return port
    except: return None
    return None

def check_open_ports(domain):
    ports_to_scan = [21, 22, 80, 443, 3306, 8080]
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        results = [executor.submit(scan_port, domain, p) for p in ports_to_scan]
        for f in concurrent.futures.as_completed(results):
            if f.result(): open_ports.append(f.result())
    return open_ports

def check_sensitive_files(url):
    files_to_check = ['/robots.txt', '/sitemap.xml', '/.env', '/.git/config']
    found = []
    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    for file in files_to_check:
        try:
            r = requests.get(base_url + file, timeout=2)
            if r.status_code == 200 and "<html" not in r.text[:20].lower():
                found.append(file)
        except: pass
    return found

def get_whois(domain):
    try:
        w = whois.whois(domain)
        creation = str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date)
        return {"registrar": w.registrar or "Diproteksi", "creation": creation.split(' ')[0]}
    except: return {"error": "Data WHOIS diproteksi."}

def check_wayback(url):
    try:
        res = requests.get(f"http://archive.org/wayback/available?url={url}", timeout=5).json()
        if res.get('archived_snapshots', {}).get('closest'):
            return {"archived": True, "url": res['archived_snapshots']['closest']['url']}
        return {"archived": False, "msg": "Belum pernah diarsipkan."}
    except: return {"archived": False, "msg": "Gagal ke Wayback Machine."}

def detect_cms(url):
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and generator.get('content'): return f"{generator['content']}"
        if 'wp-content' in res.text: return "WordPress"
        return "Custom / Tidak Terdeteksi"
    except: return "Gagal memindai struktur web."

# ROUTES
@app.route('/')
def home(): return render_template('home.html')

@app.route('/scanner')
def scanner(): return render_template('scanner.html')

@app.route('/about')
def about(): return render_template('about.html')

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json
    target_url = data.get('url')
    if not target_url.startswith(('http://', 'https://')): target_url = 'https://' + target_url
    domain = urlparse(target_url).netloc.split(':')[0]

    header_results, server_info, success = check_security_headers(target_url)
    if not success: return jsonify({"error": "Gagal menghubungi URL target. Pastikan URL aktif."}), 400

    return jsonify({
        "domain": domain,
        "pattern_warnings": analyze_url_patterns(target_url),
        "headers": header_results,
        "server_info": server_info,
        "ssl": check_ssl(domain),
        "virustotal": check_virustotal(target_url),
        "geo": get_ip_geo(domain),
        "subdomains": get_subdomains(domain),
        "dns": check_dns_security(domain),
        "open_ports": check_open_ports(domain),
        "sensitive_files": check_sensitive_files(target_url),
        "whois": get_whois(domain),
        "wayback": check_wayback(target_url),
        "cms": detect_cms(target_url)
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)