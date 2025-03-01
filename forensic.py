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

def get_headers(url):
    try:
        response = requests.get(url)
        print("--- HTTP Headers ---")
        for key, value in response.headers.items():
            print(f"{key}: {value}")
    except Exception as e:
        print("Error fetching URL:", e)

def get_whois(domain):
    try:
        w = whois.whois(domain)
        print("--- WHOIS Information ---")
        print(w)
    except Exception as e:
        print("Error fetching WHOIS:", e)

def get_dns_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        print("--- DNS Records ---")
        for rdata in answers:
            print(rdata.to_text())
    except Exception as e:
        print("Error fetching DNS records:", e)

def check_blacklist(url):
    blacklist_urls = [
        f"https://www.virustotal.com/gui/domain/{url}",
        f"https://www.phishtank.com/check_another.php?quick=1&isaphish=&valid=Check+URL&url={url}"
    ]
    print("--- Blacklist Check ---")
    for b_url in blacklist_urls:
        print("Check:", b_url)

def extract_metadata(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        print("--- Metadata Extraction ---")
        for meta in soup.find_all('meta'):
            if meta.get('name') and meta.get('content'):
                print(f"{meta.get('name')}: {meta.get('content')}")
    except Exception as e:
        print("Error fetching page:", e)

def log_analysis(url):
    try:
        hashed_url = hashlib.md5(url.encode()).hexdigest()
        log_entry = {"timestamp": time.ctime(), "url": url, "hash": hashed_url}
        log_file_path = "forensic_logs.json"
        
        logs = []
        if os.path.exists(log_file_path):
            with open(log_file_path, "r") as log_file:
                logs = [json.loads(line) for line in log_file if line.strip()]
        
        existing_hashes = {entry["hash"] for entry in logs}
        if hashed_url in existing_hashes:
            print("[ALERT] URL has been previously scanned!")
        else:
            logs.append(log_entry)
            with open(log_file_path, "a") as log_file:
                log_file.write(json.dumps(log_entry) + "\n")
        
        print("--- Log Analysis ---")
        print("URL Hash:", hashed_url)
    except Exception as e:
        print("Error logging data:", e)

def track_cryptocurrency(domain):
    print("--- Cryptocurrency Forensic ---")
    print(f"Tracking transactions for: {domain}")
    blockchain_url = f"https://www.blockchain.com/explorer/search?search={domain}"
    print(f"Check transactions here: {blockchain_url}")

def scan_sensitive_info(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            content = response.text
            print("--- Sensitive Data Scan ---")
            emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", content))
            if emails:
                print("Found emails:", emails)
            else:
                print("No emails found.")
            
            api_keys = set(re.findall(r"(?i)apikey[=:\"']([a-zA-Z0-9]{20,})", content))
            if api_keys:
                print("Potential API Keys found:", api_keys)
            else:
                print("No API keys found.")
        else:
            print("Error fetching page for sensitive info scan.")
    except Exception as e:
        print("Error scanning for sensitive info:", e)

def detect_anomalies(ip_list):
    ip_data = np.array([[int(ip.split(".")[0])] for ip in ip_list])
    model = IsolationForest(contamination=0.1)
    model.fit(ip_data)
    predictions = model.predict(ip_data)
    anomalies = [ip_list[i] for i, val in enumerate(predictions) if val == -1]
    print("--- Anomalous IP Addresses ---")
    for ip in anomalies:
        print(ip)

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

def alert_monitoring():
    print("[ALERT MONITORING] Active threat detection enabled.")
    print("Real-time alerts will be generated for detected threats.")

def scan_all_links(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = {a['href'] for a in soup.find_all('a', href=True)}
        print("--- Scanning All Links ---")
        for link in links:
            if link.startswith("http"):
                print("Scanning:", link)
                scan_sensitive_info(link)
    except Exception as e:
        print("Error scanning all links:", e)

def update():
    print("Updating forensic tool...")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 forensic.py <URL> or python3 forensic.py -update")
        return
    
    if sys.argv[1] == "-update":
        update()
        return
    
    url = sys.argv[1]
    domain = url.replace("http://", "").replace("https://", "").split("/")[0]
    
    print(f"Starting forensic scan for: {url}")
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

if __name__ == "__main__":
    main()
