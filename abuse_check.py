import re
import time
import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# Suppress SSL warnings if verify=False is used
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOG_FILE_PATH = "detection_results.txt"       # Path to your log file
OUTPUT_FILE_PATH = "abuse.txt"               # Path to save reported IPs (IP,Score)
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"  # Replace with your API key

API_URL = "https://api.abuseipdb.com/api/v2/check"

def get_configured_session() -> requests.Session:
    session = requests.Session()

    # --- Explicit Proxy Configuration ---
    session.proxies = {
        "http": "http://USERNAME:PASSWORD@PROXY_IP:PORT",
        "https": "http://USERNAME:PASSWORD@PROXY_IP:PORT"
    }
    # ------------------------------------

    retries = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
        raise_on_status=False
    )
    
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    
    session.headers.update({
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    return session

def extract_ip_addresses(file_path: str) -> list[str]:
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    unique_ips = set()
    
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                matches = ip_pattern.findall(line)
                for ip in matches:
                    unique_ips.add(ip)
    except FileNotFoundError:
        print(f"[!] Error: File '{file_path}' not found.")
        return []

    return sorted(list(unique_ips))

def check_ip_abuse(session: requests.Session, ip: str) -> dict | None:
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    try:
        response = session.get(API_URL, params=params, timeout=10, verify=False)
        
        if response.status_code == 200:
            return response.json().get('data', {})
        elif response.status_code == 401:
            print("[!] Authentication failed (401). Check your AbuseIPDB API Key.")
            return None
        elif response.status_code == 429:
            print("[!] Rate limit exceeded (429).")
            return None
        else:
            print(f"[!] Request failed for {ip} (HTTP {response.status_code}): {response.text}")
            return None
            
    except requests.RequestException as e:
        print(f"[!] Connection error for {ip}: {e}")
        return None

def main():
    print(f"[*] Reading IP addresses from '{LOG_FILE_PATH}'...")
    ip_list = extract_ip_addresses(LOG_FILE_PATH)

    if not ip_list:
        print("[!] No IP addresses found or file is empty.")
        return

    print(f"[+] Found {len(ip_list)} unique IP address(es): {', '.join(ip_list)}\n")

    session = get_configured_session()
    reported_entries = []

    for ip in ip_list:
        print(f"[*] Checking IP: {ip}...")
        data = check_ip_abuse(session, ip)

        if data:
            total_reports = data.get('totalReports', 0)
            score = data.get('abuseConfidenceScore', 0)
            country = data.get('countryCode', 'N/A')
            isp = data.get('isp', 'N/A')

            print(f"    -> Score: {score}% | Reports: {total_reports} | Country: {country} | ISP: {isp}")

            if total_reports > 0 or score > 0:
                reported_entries.append(f"{ip},{score}")
        
        time.sleep(0.5)

    if reported_entries:
        with open(OUTPUT_FILE_PATH, "w", encoding="utf-8") as out_file:
            out_file.write("IP,Score\n")
            for entry in reported_entries:
                out_file.write(f"{entry}\n")
        print(f"\n[+] Successfully wrote {len(reported_entries)} reported IP(s) to '{OUTPUT_FILE_PATH}'.")
    else:
        print("\n[*] No reported IPs found from the extracted list.")

if __name__ == "__main__":
    main()
