import csv
import json
import re
import subprocess
import sys
import time
import requests
import urllib3

urllib3.disable_warnings()

# ==================================================================
# Configuration
# ==================================================================
QRADAR = "https://X.X.X.X"  # SIEM IP
SEC_TOKEN = "YOUR_QRADAR_SEC_TOKEN"

CSV_FILE = "training.csv"
OUTPUT_FILE = "training.txt"
TRAINING_SCRIPT = "training-2.py"

MAX_CHARS = 3000
HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH")

headers = {"SEC": SEC_TOKEN, "Version": "16.0", "Accept": "application/json"}

# Regex patterns
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

    raw = length_cap(raw)
    return raw

# ==================================================================
# Step 1: Fetching Log Data from QRadar Ariel
# ==================================================================
aql_query = (
    'SELECT utf8(payload) FROM events '
    "WHERE logsourcename(logsourceid) ilike '%F5%' "
    "AND \"WAF VIP\"='www.example.com' "
    "AND NOT (INCIDR('10.0.0.0/8',sourceip) "
    "AND NOT INCIDR('192.168.0.0/16',sourceip) "
    "AND NOT INCIDR('172.16.0.0/12',sourceip) "
    "AND NOT INCIDR('X.X.X.X/29',sourceip) ) "
    "AND \"F5 Action\"!='blocked' "
    "LAST 240 HOURS"
)

with open(CSV_FILE, "w", encoding="utf-8", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["payload"])

print("[+] Submitting AQL query to QRadar...")
response = requests.post(
    f"{QRADAR}/api/ariel/searches",
    headers=headers,
    params={"query_expression": aql_query},
    verify=False,
)
response.raise_for_status()
search_id = response.json()["search_id"]
print(f"[+] Search ID created: {search_id}")

while True:
    status_resp = requests.get(
        f"{QRADAR}/api/ariel/searches/{search_id}",
        headers=headers,
        verify=False,
    ).json()

    status = status_resp.get("status")
    print(f"[*] Search Status: {status}")

    if status == "COMPLETED":
        break
    elif status in ["CANCELED", "ERROR"]:
        raise Exception(f"[-] QRadar search failed with status: {status}")

    time.sleep(5)

print("[+] Fetching raw search results...")
results_resp = requests.get(
    f"{QRADAR}/api/ariel/searches/{search_id}/results",
    headers=headers,
    verify=False,
).json()

events = results_resp.get("events", [])
print(f"[+] Found {len(events)} events. Exporting to raw CSV ({CSV_FILE})...")

with open(CSV_FILE, "a", encoding="utf-8", newline="") as f:
    writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
    for event in events:
        payload = event.get("utf8_payload")
        if not payload:
            continue
        payload = payload.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
        payload = " ".join(payload.split())
        writer.writerow([payload])

print(f"[+] Data successfully saved to {CSV_FILE}!\n")

# ==================================================================
# Step 2: Run Text Normalization Pipeline
# ==================================================================
print(f"[*] Starting log normalization pipeline on {CSV_FILE}...")
outputs = []

with open(CSV_FILE, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        if "cs3=" not in line:
            continue

        match = CS3_PATTERN.search(line)
        if not match:
            continue

        http_raw = match.group(1)
        http_clean = clean_http_request(http_raw)

        if http_clean:
            outputs.append(http_clean)

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    for req in outputs:
        f.write(req + "\n")

print("-" * 60)
print(f"[+] Extracted and normalized {len(outputs)} total HTTP requests.")
print(f"[+] Operational data saved to: {OUTPUT_FILE}")
print("-" * 60)

# ==================================================================
# Step 3: Trigger Training Script
# ==================================================================
print(f"[*] Launching model training script: {TRAINING_SCRIPT}...")

try:
    result = subprocess.run(
        [sys.executable, TRAINING_SCRIPT],
        check=True,
        text=True,
        capture_output=False
    )
    print(f"\n[+] {TRAINING_SCRIPT} executed successfully.")
    
except subprocess.CalledProcessError as e:
    print(f"\n[-] Error running {TRAINING_SCRIPT}. Exit code: {e.returncode}")
except FileNotFoundError:
    print(f"\n[-] Error: Could not find '{TRAINING_SCRIPT}' in the local directory.")
