import requests

feeds = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
]

clean_ips = []

for url in feeds:

    response = requests.get(url)

    if response.status_code == 200:

        data = response.text.splitlines()

        for line in data:

            if not line.startswith("#") and line.strip() != "":
                clean_ips.append(line)

        print(f"Downloaded feed: {url}")

    else:
        print(f"Failed to download: {url}")

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