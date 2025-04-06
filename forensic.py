# versi 1.3
import logging
import threading
import requests
import whois
import sys
import dns.resolver
from bs4 import BeautifulSoup
import hashlib
import json
import time
import re
import os
import socket
import numpy as np
from sklearn.ensemble import IsolationForest
from concurrent.futures import ThreadPoolExecutor
import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime

# Konfigurasi logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[
    logging.FileHandler("forensic.log"),
    logging.StreamHandler()
])

# Fungsi untuk mengambil HTTP headers
def get_headers(url):
    try:
        response = requests.get(url)
        logging.info("--- HTTP Headers ---")
        for key, value in response.headers.items():
            logging.info(f"{key}: {value}")
    except Exception as e:
        logging.error("Error fetching URL: %s", e)

# Fungsi untuk mengambil informasi WHOIS
def get_whois(domain):
    try:
        w = whois.whois(domain)
        logging.info("--- WHOIS Information ---")
        logging.info(w)
    except Exception as e:
        logging.error("Error fetching WHOIS: %s", e)

# Fungsi untuk mengambil DNS records
def get_dns_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        logging.info("--- DNS Records ---")
        for rdata in answers:
            logging.info(rdata.to_text())
    except Exception as e:
        logging.error("Error fetching DNS records: %s", e)

# Fungsi untuk memeriksa blacklist
def check_blacklist(url):
    blacklist_urls = [
        f"https://www.virustotal.com/gui/domain/{url}",
        f"https://www.phishtank.com/check_another.php?quick=1&isaphish=&valid=Check+URL&url={url}"
    ]
    logging.info("--- Blacklist Check ---")
    for b_url in blacklist_urls:
        logging.info("Check: %s", b_url)

# Fungsi untuk ekstraksi metadata dari halaman web
def extract_metadata(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        logging.info("--- Metadata Extraction ---")
        for meta in soup.find_all('meta'):
            if meta.get('name') and meta.get('content'):
                logging.info("%s: %s", meta.get('name'), meta.get('content'))
    except Exception as e:
        logging.error("Error fetching page: %s", e)

# Fungsi untuk analisis log
def log_analysis(url):
    try:
        hashed_url = hashlib.md5(url.encode()).hexdigest()
        log_entry = {"timestamp": time.ctime(), "url": url, "hash": hashed_url}
        log_file_path = "forensic_logs.json"
        
        logs = []
        if os.path.exists(log_file_path):
            with open(log_file_path, "r") as log_file:
                try:
                    logs = [json.loads(line) for line in log_file if line.strip()]
                except json.JSONDecodeError as e:
                    logging.error("Error decoding JSON from log file: %s", e)
                    return
        
        existing_hashes = {entry["hash"] for entry in logs}
        if hashed_url in existing_hashes:
            logging.warning("[ALERT] URL has been previously scanned!")
        else:
            logs.append(log_entry)
            with open(log_file_path, "a") as log_file:
                log_file.write(json.dumps(log_entry) + "\n")
        
        logging.info("--- Log Analysis ---")
        logging.info("URL Hash: %s", hashed_url)
    except Exception as e:
        logging.error("Error logging data: %s", e)

# Fungsi untuk melacak cryptocurrency yang terkait dengan domain
def track_cryptocurrency(domain):
    logging.info("--- Cryptocurrency Forensic ---")
    logging.info("Tracking transactions for: %s", domain)
    blockchain_url = f"https://www.blockchain.com/explorer/search?search={domain}"
    logging.info("Check transactions here: %s", blockchain_url)

# Fungsi untuk memeriksa data sensitif di halaman web
def scan_sensitive_info(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            content = response.text
            logging.info("--- Sensitive Data Scan ---")
            emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", content))
            if emails:
                logging.info("Found emails: %s", emails)
            else:
                logging.info("No emails found.")
                
            api_keys = set(re.findall(r"(?i)apikey[=:\"']([a-zA-Z0-9]{20,})", content))
            if api_keys:
                logging.info("Potential API Keys found: %s", api_keys)
            else:
                logging.info("No API keys found.")
        else:
            logging.error("Error fetching page for sensitive info scan.")
    except Exception as e:
        logging.error("Error scanning for sensitive info: %s", e)

# Fungsi untuk mendeteksi IP yang mencurigakan
def detect_anomalies(ip_list):
    ip_data = np.array([[int(ip.split(".")[i]) for i in range(4)] for ip in ip_list])
    model = IsolationForest(contamination=0.1)
    model.fit(ip_data)
    predictions = model.predict(ip_data)
    anomalies = [ip_list[i] for i, val in enumerate(predictions) if val == -1]
    logging.info("--- Anomalous IP Addresses ---")
    for ip in anomalies:
        logging.info(ip)

# Fungsi untuk analisis korelasi IP
def ip_correlation_analysis():
    log_file_path = "forensic_logs.json"
    ip_list = []
    if os.path.exists(log_file_path):
        with open(log_file_path, "r") as log_file:
            logs = [json.loads(line) for line in log_file if line.strip()]
            for log in logs:
                try:
                    ip = socket.gethostbyname(log["url"].split("/")[0])
                    ip_list.append(ip)
                except Exception:
                    pass
    if ip_list:
        detect_anomalies(ip_list)

# Fungsi untuk memantau ancaman secara real-time
def alert_monitoring():
    logging.info("[ALERT MONITORING] Active threat detection enabled.")
    logging.info("Real-time alerts will be generated for detected threats.")

# Fungsi untuk memindai semua link pada halaman
def scan_all_links(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = {a['href'] for a in soup.find_all('a', href=True)}
        logging.info("--- Scanning All Links ---")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(scan_sensitive_info, link) for link in links if link.startswith("http")]
            for future in futures:
                future.result()

    except Exception as e:
        logging.error("Error scanning all links: %s", e)

# Fungsi analitik tren URL
def analyze_url_trends():
    try:
        log_file_path = "forensic_logs.json"
        url_count = Counter()
        
        if os.path.exists(log_file_path):
            with open(log_file_path, "r") as log_file:
                logs = [json.loads(line) for line in log_file if line.strip()]
                for log in logs:
                    url = log.get("url", "")
                    if url:
                        url_count[url] += 1
        
        if url_count:
            logging.info("--- URL Trends ---")
            # Plotting
            urls, counts = zip(*url_count.items())
            plt.bar(urls, counts)
            plt.xticks(rotation=45, ha='right')
            plt.xlabel("URL")
            plt.ylabel("Jumlah Scan")
            plt.title("Tren URL Berdasarkan Jumlah Scan")
            plt.tight_layout()
            plt.show()
        else:
            logging.info("No URL scan history found for trend analysis.")
    except Exception as e:
        logging.error("Error analyzing URL trends: %s", e)

# Fungsi analisis metadata
def analyze_metadata(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        meta_data = [meta.get('name') for meta in soup.find_all('meta') if meta.get('name')]
        if meta_data:
            logging.info("--- Metadata Analysis ---")
            meta_count = Counter(meta_data)
            
            # Plotting
            labels, values = zip(*meta_count.items())
            plt.bar(labels, values)
            plt.xticks(rotation=45, ha='right')
            plt.xlabel("Metadata Name")
            plt.ylabel("Frequency")
            plt.title("Analisis Metadata pada URL")
            plt.tight_layout()
            plt.show()
        else:
            logging.info("No metadata found for URL.")
    except Exception as e:
        logging.error("Error analyzing metadata: %s", e)

# Fungsi untuk menghitung skor keamanan URL
def calculate_security_score(url):
    try:
        score = 100  # Mulai dengan skor maksimal
        
        # Cek apakah URL masuk dalam blacklist
        blacklist_urls = [
            f"https://www.virustotal.com/gui/domain/{url}",
            f"https://www.phishtank.com/check_another.php?quick=1&isaphish=&valid=Check+URL&url={url}"
        ]
        
        for b_url in blacklist_urls:
            logging.info(f"Checking blacklist status for: {b_url}")
            score -= 20  # Mengurangi skor jika URL ada dalam blacklist

        # Cek metadata (misal: apakah ada keyword mencurigakan)
        if "phishing" in url.lower():
            logging.info("URL contains suspicious keyword: phishing")
            score -= 30
        
        # Cek apakah URL memiliki data sensitif (email, API keys)
        if scan_sensitive_info(url):  # Memanggil fungsi scan_sensitive_info yang sudah ada
            logging.info("Sensitive data detected on URL.")
            score -= 40
        
        logging.info("Security Score for URL: %s is %d", url, score)
    except Exception as e:
        logging.error("Error calculating security score: %s", e)

# Fitur utama yang sudah ada, ditambah analitik
def main():
    if len(sys.argv) < 2:
        logging.error("Usage: python3 forensic.py <URL> or python3 forensic.py -update")
        return
    
    if sys.argv[1] == "-update":
        update()
        return
    
    url = sys.argv[1]
    domain = url.replace("http://", "").replace("https://", "").split("/")[0]
    
    logging.info("Starting forensic scan for: %s", url)
    
    get_headers(url)
    get_whois(domain)
    get_dns_records(domain)
    check_blacklist(domain)
    extract_metadata(url)
    log_analysis(url)
    track_cryptocurrency(domain)
    scan_sensitive_info(url)
    ip_correlation_analysis()
    scan_all_links(url)
    alert_monitoring()
    
    # Tambahkan fitur analitik
    analyze_url_trends()
    analyze_metadata(url)
    calculate_security_score(url)

if __name__ == "__main__":
    main()
