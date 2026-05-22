import requests

url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

response = requests.get(url)

if response.status_code == 200:
    data = response.text.splitlines()

    clean_ips = []

    for line in data:
        if not line.startswith("#") and line.strip() != "":
            clean_ips.append(line)

    with open("data/malicious_ips.txt", "w") as file:
        for ip in clean_ips:
            file.write(ip + "\n")

    print("Threat feed downloaded successfully.")

else:
    print("Failed to download threat feed.")
