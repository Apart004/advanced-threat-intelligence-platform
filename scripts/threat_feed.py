import requests

url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

response = requests.get(url)

if response.status_code == 200:
    data = response.text

    with open("data/malicious_ips.txt", "w") as file:
        file.write(data)

    print("Threat feed downloaded successfully.")

else:
    print("Failed to download threat feed.")
