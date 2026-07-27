import re
import requests
import urllib3
from collections import defaultdict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

QRADAR_HOST = "https://X.X.X.X"  # SIEM IP
SEC_TOKEN = "YOUR_QRADAR_SEC_TOKEN"
VERSION = "26.0"

HEADERS = {
    "SEC": SEC_TOKEN,
    "Version": VERSION,
    "Accept": "application/json"
}

def parse_offenses(filepath="offense.txt"):
    offenses = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(",")
                if len(parts) == 2:
                    offense_id, ip = parts[0].strip(), parts[1].strip()
                    if offense_id.isdigit():
                        offenses.append((int(offense_id), ip))
    except FileNotFoundError:
        print(f"[!] Warning: File {filepath} not found.")
    return offenses

def parse_vt(filepath="vt.txt"):
    vt_data = {}
    pattern = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}).*?M:(\d+)')
    try:
        with open(filepath, "r") as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    ip, malicious_count = match.group(1), int(match.group(2))
                    vt_data[ip] = malicious_count
    except FileNotFoundError:
        print(f"[!] Warning: File {filepath} not found.")
    return vt_data

def parse_abuse(filepath="abuse.txt"):
    abuse_data = {}
    pattern = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}).*?(\d+)')
    try:
        with open(filepath, "r") as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    ip, score = match.group(1), int(match.group(2))
                    abuse_data[ip] = score
    except FileNotFoundError:
        print(f"[!] Warning: File {filepath} not found.")
    return abuse_data

def parse_detection_results(filepath="detection_results.txt"):
    ip_scores = defaultdict(list)
    pattern = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}).*?(\d+\.\d+)')
    try:
        with open(filepath, "r") as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    ip, score = match.group(1), float(match.group(2))
                    ip_scores[ip].append(score)
    except FileNotFoundError:
        print(f"[!] Warning: File {filepath} not found.")

    return {ip: max(scores) for ip, scores in ip_scores.items()}

def close_qradar_offense(offense_id):
    url = f"{QRADAR_HOST}/api/siem/offenses/{offense_id}"
    params = {
        "status": "CLOSED",
        "closing_reason_id": 1
    }
    try:
        response = requests.post(url, headers=HEADERS, params=params, verify=False)
        if response.status_code == 200:
            print(f"[SUCCESS] Offense {offense_id} successfully closed.")
            return True
        else:
            print(f"[FAILURE] Offense {offense_id} - HTTP {response.status_code}: {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to connect to QRadar for Offense {offense_id}: {e}")
        return False

if __name__ == "__main__":
    print("[*] Reading mapping from offense.txt...")
    offenses = parse_offenses("offense.txt")

    print("[*] Parsing threat intelligence and detection files...")
    vt_data = parse_vt("vt.txt")
    abuse_data = parse_abuse("abuse.txt")
    detection_data = parse_detection_results("detection_results.txt")

    not_closed_records = []

    print("[*] Evaluating offenses...")
    for offense_id, ip in offenses:
        vt_score = vt_data.get(ip)
        abuse_score = abuse_data.get(ip)
        anomaly_score = detection_data.get(ip)

        vt_valid = (vt_score is not None) and (vt_score == 0)
        abuse_valid = (abuse_score is not None) and (abuse_score < 50)
        anomaly_valid = (anomaly_score is not None) and (anomaly_score < 0.2)

        if vt_valid and abuse_valid and anomaly_valid:
            print(f"[*] Closing Offense ID {offense_id} (IP: {ip})...")
            success = close_qradar_offense(offense_id)
            if not success:
                vt_str = f"M:{vt_score}" if vt_score is not None else "N/A"
                anom_str = str(anomaly_score) if anomaly_score is not None else "N/A"
                abuse_str = str(abuse_score) if abuse_score is not None else "N/A"
                not_closed_records.append(f"{ip},{offense_id},{vt_str},{anom_str},{abuse_str}\n")
        else:
            vt_str = f"M:{vt_score}" if vt_score is not None else "N/A"
            anom_str = str(anomaly_score) if anomaly_score is not None else "N/A"
            abuse_str = str(abuse_score) if abuse_score is not None else "N/A"

            not_closed_records.append(f"{ip},{offense_id},{vt_str},{anom_str},{abuse_str}\n")

    output_filename = "notclosedoffense.txt"
    with open(output_filename, "w") as f:
        f.write("IP,OffenseID,VirusTotal,AnomalyScore,AbuseIPScore\n")
        f.writelines(not_closed_records)

    print(f"[*] Completed! Saved {len(not_closed_records)} unclosed offense(s) to '{output_filename}'.")
