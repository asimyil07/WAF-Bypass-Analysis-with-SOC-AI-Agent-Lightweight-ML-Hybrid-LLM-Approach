import requests 
import urllib3
import time
import json
import csv
import re
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================================================================
# Configuration
# ==================================================================
QRADAR = "https://X.X.X.X"  # SIEM IP
SEC_TOKEN = "YOUR_QRADAR_SEC_TOKEN"
OFFENSE_NAME = "AI_Test_WAF_1"

headers = {
    "SEC": SEC_TOKEN,
    "Version": "16.0",
    "Accept": "application/json"
}

CSV_FILE = "payloads.csv"
OUTPUT_FILE = "payloads.txt"
RESULT_FILE = "detection_results.txt"
OFFENSE_FILE = "offense.txt"

DETECTION_SERVICE_URL = "http://127.0.0.1:8000/predict"
MAX_CHARS = 3000
HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH")

CS3_PATTERN = re.compile(r"cs3=(.*)", re.DOTALL)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
UUID_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}\b"
)
HEX_PATTERN = re.compile(r"\b[a-fA-F0-9]{8,}\b")
NUM_PATTERN = re.compile(r"\b\d+\b")

def mask_ips(text: str) -> str:
    return IP_PATTERN.sub("<IP>", text)

def normalize_quotes(text: str) -> str:
    text = text.replace('\\"', '"')
    text = text.replace('""', '"')
    text = text.replace("''", '"')
    return text

def flatten_newlines(text: str) -> str:
    return (
        text.replace("\\r\\n", " ")
            .replace("\\n", " ")
            .replace("\r\n", " ")
            .replace("\n", " ")
    )

def normalize_values(text: str) -> str:
    text = UUID_PATTERN.sub("<UUID>", text)
    text = HEX_PATTERN.sub("<HEX>", text)
    text = NUM_PATTERN.sub("<NUM>", text)
    return text

def length_cap(text: str) -> str:
    if len(text) <= MAX_CHARS:
        return text
    return text[:MAX_CHARS].rsplit(" ", 1)[0] + " [TRUNCATED]"

def clean_http_request(raw: str) -> str:
    raw = flatten_newlines(raw)
    raw = normalize_quotes(raw)
    raw = mask_ips(raw)
    raw = normalize_values(raw)
    raw = re.sub(r"\s+", " ", raw).strip()

    if not raw.startswith(HTTP_METHODS):
        return ""

    return length_cap(raw)

# ==================================================================
# Step 1: Fetch Offenses & Record CSV & Offense TXT
# ==================================================================

open(CSV_FILE, "w", encoding="utf-8").close()
open(OFFENSE_FILE, "w", encoding="utf-8").close()

print("[*] Fetching matching open offenses...")
url = f'{QRADAR}/api/siem/offenses?filter=status="OPEN"'
resp = requests.get(url, headers=headers, verify=False)
resp.raise_for_status()

matching_offenses = []
for offense in resp.json():
    description = offense.get("description", "")
    if OFFENSE_NAME in description:
        matching_offenses.append({
            "id": offense["id"],
            "description": description
        })

if not matching_offenses:
    print(f"[-] No matching open offense found: {OFFENSE_NAME}")
    sys.exit(0)

print(f"[+] Found {len(matching_offenses)} matching offense(s)")

for offense in matching_offenses:
    offense_id = offense["id"]

    print("\n" + "=" * 100)
    print(f"PROCESSING OFFENSE ID: {offense_id}")
    print("=" * 100)

    ip_query = f"SELECT sourceip FROM events WHERE INOFFENSE({offense_id}) LIMIT 100 LAST 70 HOURS"
    resp = requests.post(f"{QRADAR}/api/ariel/searches", headers=headers, params={"query_expression": ip_query}, verify=False)
    resp.raise_for_status()
    search_id = resp.json()["search_id"]

    while True:
        status = requests.get(f"{QRADAR}/api/ariel/searches/{search_id}", headers=headers, verify=False).json()
        if status.get("status") == "COMPLETED":
            break
        time.sleep(2)

    ip_results = requests.get(f"{QRADAR}/api/ariel/searches/{search_id}/results", headers=headers, verify=False).json()
    unique_ips = {row.get("sourceip") for row in ip_results.get("events", []) if row.get("sourceip")}

    if not unique_ips:
        print(f"[-] No source IPs found for offense {offense_id}.")
        continue

    with open(OFFENSE_FILE, "a", encoding="utf-8") as off_f:
        for ip in sorted(unique_ips):
            off_f.write(f"{offense_id},{ip}\n")

    print(f"[+] Found {len(unique_ips)} unique target IPs. Querying F5 payloads dynamically...")

    ip_list_str = ", ".join(f"'{ip}'" for ip in unique_ips)
    payload_query = (
        f"SELECT sourceip, utf8(payload) FROM events "
        f"WHERE LOGSOURCENAME(logsourceid) ILIKE '%F5%' "
        f"AND destinationip='X.X.X.X' "
        f"AND sourceip IN ({ip_list_str}) "
        f"LIMIT 300 LAST 70 HOURS"
    )

    response = requests.post(f"{QRADAR}/api/ariel/searches", headers=headers, params={"query_expression": payload_query}, verify=False)
    response.raise_for_status()
    payload_search_id = response.json()["search_id"]

    while True:
        status = requests.get(f"{QRADAR}/api/ariel/searches/{payload_search_id}", headers=headers, verify=False).json()
        if status.get("status") == "COMPLETED":
            break
        time.sleep(2)

    payload_results = requests.get(f"{QRADAR}/api/ariel/searches/{payload_search_id}/results", headers=headers, verify=False).json()

    with open(CSV_FILE, "a", encoding="utf-8", newline='') as f:
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        for event in payload_results.get("events", []):
            src_ip = event.get("sourceip") or "0.0.0.0"
            payload = event.get("utf8(payload)") or event.get("utf8_payload") or event.get("payload")

            if not payload:
                continue

            payload = flatten_newlines(payload)
            payload = " ".join(payload.split())
            writer.writerow([src_ip, payload])

print(f"\n[+] Raw log data recording finished -> {CSV_FILE}")
print(f"[+] Offense & IP mappings recorded -> {OFFENSE_FILE}")

# ==================================================================
# Step 2: Normalization Pipeline
# ==================================================================
print("\n" + "=" * 100)
print("STARTING NORMALIZATION PROCESS")
print("=" * 100)

mapped_outputs = []
with open(CSV_FILE, "r", encoding="utf-8", errors="ignore") as f:
    reader = csv.reader(f)
    for row in reader:
        if not row or len(row) < 2:
            continue
            
        src_ip = row[0]
        line = row[1]
        
        if "cs3=" not in line:
            continue

        match = CS3_PATTERN.search(line)
        if not match:
            continue

        http_raw = match.group(1)
        http_clean = clean_http_request(http_raw)

        if http_clean:
            mapped_outputs.append({
                "ip": src_ip,
                "normalized_payload": http_clean
            })

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(mapped_outputs, f, indent=4)

print(f"[+] Extracted {len(mapped_outputs)} HTTP requests mapped to tracking IPs")

# ==================================================================
# Step 3: Fast HTTP Inference Trigger
# ==================================================================
print("\n" + "=" * 100)
print("TRIGGERING DETECTION INFERENCE")
print("=" * 100)

if not mapped_outputs:
    print("[-] No normalized payloads to analyze.")
    sys.exit(0)

try:
    res = requests.post(DETECTION_SERVICE_URL, json=mapped_outputs, timeout=30)
    res.raise_for_status()

    result_data = res.json().get("logs", [])

    with open(RESULT_FILE, "w", encoding="utf-8") as outfile:
        for line in result_data:
            print(line, end="")
            outfile.write(line)

    print(f"\n[+] Detection finished! Results written to {RESULT_FILE}")

except requests.exceptions.ConnectionError:
    print(f"\n[!] Error: Could not connect to detection service at {DETECTION_SERVICE_URL}.")
except Exception as e:
    print(f"\n[!] Error during detection invocation: {e}")
