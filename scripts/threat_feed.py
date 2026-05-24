import requests
from datetime import datetime

feeds = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
]

clean_ips = []

log_file = "logs/threat_feed.log"


def write_log(message):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(log_file, "a") as log:
        log.write(f"[{timestamp}] {message}\n")


for url in feeds:

    response = requests.get(url)

    if response.status_code == 200:

        data = response.text.splitlines()

        for line in data:

            if not line.startswith("#") and line.strip() != "":
                clean_ips.append(line)

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


print("Combined threat feeds saved successfully.")
print(f"Total IPs collected: {total_ips_before}")
print(f"Duplicates removed: {duplicates_removed}")
print(f"Final clean IPs: {total_ips_after}")

write_log(f"Total IPs collected: {total_ips_before}")
write_log(f"Duplicates removed: {duplicates_removed}")
write_log(f"Final clean IPs: {total_ips_after}")
write_log("Threat feed processing completed successfully")