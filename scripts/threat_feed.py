import requests
from datetime import datetime
import json

feeds = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
]

clean_ips = []
structured_records = []
source_counts = {}

log_file = "logs/threat_feed.log"


def write_log(message):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(log_file, "a") as log:
        log.write(f"[{timestamp}] {message}\n")


for url in feeds:

    response = requests.get(url, timeout=10)

    if response.status_code == 200:

        data = response.text.splitlines()

        source_counts[url] = 0

        for line in data:

            if not line.startswith("#") and line.strip() != "":

                clean_ips.append(line)

                source_counts[url] += 1

                # Risk scoring logic
                if "abuse.ch" in url:
                    risk_score = 95
                    severity = "High"
                else:
                    risk_score = 80
                    severity = "Medium"

                record = {
                    "ip": line,
                    "source": url,
                    "status": "malicious",
                    "risk_score": risk_score,
                    "severity": severity,
                    "collected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }

                structured_records.append(record)

        print(f"Downloaded feed: {url}")
        write_log(f"Successfully downloaded feed: {url}")

    else:

        print(f"Failed to download: {url}")
        write_log(f"Failed to download feed: {url}")


total_ips_before = len(clean_ips)

clean_ips = list(set(clean_ips))

total_ips_after = len(clean_ips)

duplicates_removed = total_ips_before - total_ips_after


with open("data/malicious_ips.txt", "w") as file:

    for ip in clean_ips:
        file.write(ip + "\n")


with open("data/threat_records.json", "w") as json_file:

    json.dump(structured_records, json_file, indent=4)


print("\n--- Threat Intelligence Analytics ---")
print(f"Total IPs collected: {total_ips_before}")
print(f"Duplicates removed: {duplicates_removed}")
print(f"Final clean IPs: {total_ips_after}")

for source, count in source_counts.items():
    print(f"{source} -> {count} records")

print("\nCombined threat feeds saved successfully.")

write_log(f"Total IPs collected: {total_ips_before}")
write_log(f"Duplicates removed: {duplicates_removed}")
write_log(f"Final clean IPs: {total_ips_after}")

for source, count in source_counts.items():
    write_log(f"{source} -> {count} records")

write_log("Threat feed processing completed successfully")