# versi 1.2
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

# Validasi URL
def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// atau https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...atau alamat IP
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...atau alamat IPv6
        r'(?::\d+)?'  # port optional
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

# Analisis Tren URL - untuk visualisasi
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

# Analisis Metadata untuk visualisasi
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

# Skor Risiko Keamanan URL
def calculate_security_score(url):
    try:
        score = 100  # Mulai dengan skor maksimal
        
        # Cek apakah URL masuk dalam blacklist
        blacklist_urls = [
            f"https://www.virustotal.com/gui/domain/{url}",
            f"https://www.phishtank.com/check_another.php?quick=1&isaphish=&valid=Check+URL&url={url}"
        ]
        
        for b_url in blacklist_urls:
            # Simulasi pengecekan (sebaiknya menggunakan API atau scraping untuk cek blacklist yang lebih akurat)
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

# Menambah analisis log
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

# Fitur utama yang sudah ada, ditambah analitik
def main():
    if len(sys.argv) < 2:
        logging.error("Usage: python3 forensic.py <URL> or python3 forensic.py -update")
        return
    
    if sys.argv[1] == "-update":
        update()
        return
    
    url = sys.argv[1]
    if not is_valid_url(url):
        logging.error("Invalid URL provided.")
        return
    
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
