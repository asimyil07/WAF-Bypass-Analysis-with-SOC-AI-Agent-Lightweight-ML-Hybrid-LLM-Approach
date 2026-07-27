import re
import time
import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
LOG_FILE_PATH = "detection_results.txt"
OUTPUT_FILE_PATH = "vt.txt"

BATCH_SIZE = 4
BATCH_DELAY_SECONDS = 65

def get_configured_session(api_key: str) -> requests.Session:
    session = requests.Session()

    session.proxies = {
        "http": "http://USERNAME:PASSWORD@PROXY_IP:PORT",
        "https": "http://USERNAME:PASSWORD@PROXY_IP:PORT"
    }

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
        "accept": "application/json",
        "x-apikey": api_key,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    })
    
    return session

def extract_unique_ips(file_path: str) -> list[str]:
    anomaly_pattern = re.compile(r'\[((?:\d{1,3}\.){3}\d{1,3})\]\s+\[ANOMALY\]')
    unique_ips = set()
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                match = anomaly_pattern.search(line)
                if match:
                    unique_ips.add(match.group(1))
    except FileNotFoundError:
        print(f"[-] File not found: {file_path}")
        return []

    return sorted(list(unique_ips))

def query_virustotal_ip(session: requests.Session, ip: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    
    try:
        response = session.get(url, timeout=10, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            total_vendors = sum(stats.values())
            
            return {
                "malicious": malicious_count,
                "suspicious": suspicious_count,
                "total": total_vendors,
                "summary": f"M:{malicious_count} | S:{suspicious_count} / {total_vendors}"
            }
        
        elif response.status_code == 429:
            print(f"[!] Rate limit hit for {ip}. Waiting 65 seconds...")
            time.sleep(65)
            return query_virustotal_ip(session, ip)
        else:
            print(f"[-] Error fetching {ip}: HTTP {response.status_code}")
            return {"malicious": "N/A", "suspicious": "N/A", "total": "N/A", "summary": "N/A"}
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed for {ip}: {e}")
        return {"malicious": "ERROR", "suspicious": "ERROR", "total": "ERROR", "summary": "ERROR"}

def main():
    print("[+] Extracting IP addresses tagged as ANOMALY from log file...")
    ips = extract_unique_ips(LOG_FILE_PATH)
    
    if not ips:
        print("[-] No ANOMALY IP addresses found.")
        return

    print(f"[+] Found {len(ips)} unique ANOMALY IP address(es): {', '.join(ips)}\n")

    session = get_configured_session(VT_API_KEY)
    results = []

    for i in range(0, len(ips), BATCH_SIZE):
        batch = ips[i:i + BATCH_SIZE]
        
        for ip in batch:
            print(f"[+] Querying VirusTotal for {ip}...")
            vt_data = query_virustotal_ip(session, ip)
            print(f"    -> VT Score: {vt_data['summary']}")
            results.append((ip, vt_data))
        
        if i + BATCH_SIZE < len(ips):
            print(f"[*] Batch complete. Waiting {BATCH_DELAY_SECONDS} seconds before the next batch...")
            time.sleep(BATCH_DELAY_SECONDS)

    print(f"\n[+] Writing results to '{OUTPUT_FILE_PATH}'...")
    with open(OUTPUT_FILE_PATH, "w", encoding="utf-8") as out_file:
        out_file.write("IP,Malicious,Suspicious,Total_Vendors,Summary\n")
        for ip, vt_data in results:
            out_file.write(f"{ip},{vt_data['malicious']},{vt_data['suspicious']},{vt_data['total']},{vt_data['summary']}\n")

    print("[+] Completed successfully.")

if __name__ == "__main__":
    main()
