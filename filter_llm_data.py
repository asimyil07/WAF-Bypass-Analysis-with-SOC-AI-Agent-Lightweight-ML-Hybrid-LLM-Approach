import csv
import re

OFFENSE_FILE = "notclosedoffense.txt"
DETECTION_FILE = "detection_results.txt"
OUTPUT_FILE = "LLMdata.txt"

valid_ips = set()

with open(OFFENSE_FILE, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)

    for row in reader:
        ip = row["IP"].strip()
        vt = row["VirusTotal"].strip()
        abuse = row["AbuseIPScore"].strip()
        anomaly = float(row["AnomalyScore"])

        vt_ok = vt in ("M:0", "N/A")

        if abuse == "N/A":
            abuse_ok = True
        else:
            try:
                abuse_ok = int(abuse) < 100
            except:
                abuse_ok = False

        if vt_ok and abuse_ok and anomaly > 0.1:
            valid_ips.add(ip)

print(f"[+] Valid IP count: {len(valid_ips)}")

header_re = re.compile(
    r'^\[(.*?)\]\s+\[ANOMALY\]\s+score=([0-9.]+)',
    re.IGNORECASE
)

with open(DETECTION_FILE, encoding="utf-8", errors="ignore") as fin, \
     open(OUTPUT_FILE, "w", encoding="utf-8") as fout:

    lines = fin.readlines()

    i = 0
    while i < len(lines):
        m = header_re.match(lines[i])

        if not m:
            i += 1
            continue

        ip = m.group(1)
        score = float(m.group(2))

        payload = ""
        if i + 1 < len(lines):
            payload = lines[i + 1].strip()

        if ip in valid_ips and score > 0.1:
            fout.write(f"{ip}\t{payload}\n")

        i += 1

print(f"[+] Finished. Output written to: {OUTPUT_FILE}")
