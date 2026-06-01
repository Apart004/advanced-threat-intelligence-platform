import os
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv
from pymongo import MongoClient, errors

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.getenv("DB_NAME", "threat_intel_db")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "indicators")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

def get_db_connection():
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
        client.server_info()
        db = client[DB_NAME]
        return db[COLLECTION_NAME]
    except errors.ServerSelectionTimeoutError:
        print("[!] Database offline.")
        return None

def save_to_mongodb(ip_list, source_url):
    collection = get_db_connection()
    if collection is None:
        return False

    duplicates_skipped = 0
    newly_inserted = 0

    for ip in ip_list:
        ip = ip.strip()
        if not ip or ip.startswith("#"):
            continue

        existing = collection.find_one({"indicator": ip})
        if existing:
            duplicates_skipped += 1
            continue

        threat_record = {
            "indicator": ip,
            "type": "ip",
            "source": source_url,
            "timestamp": datetime.now(timezone.utc),
            "status": "active"
        }

        try:
            collection.insert_one(threat_record)
            newly_inserted += 1
        except Exception as e:
            print(f"[-] Insertion failure: {e}")

    print(f"\n[{source_url}]")
    print(f"   -> Newly Cataloged: {newly_inserted}")
    print(f"   -> Duplicates Filtered: {duplicates_skipped}")
    return True

def fetch_flat_feeds():
    """Feeds 1 & 2: Feodo Tracker + Emerging Threats (plain IP lists)."""
    urls = [
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    ]
    for url in urls:
        try:
            print(f"\n[*] Downloading: {url}")
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                ips = response.text.splitlines()
                clean_ips = [ip.strip() for ip in ips
                             if ip.strip() and not ip.startswith("#")]
                save_to_mongodb(clean_ips, url)
        except Exception as e:
            print(f"[-] Feed error: {e}")

def fetch_otx_feed():
    """Feed 3: AlienVault OTX - pulls malicious IPs from subscribed pulses."""
    if not OTX_API_KEY:
        print("\n[!] OTX_API_KEY not set in .env - skipping OTX feed.")
        return

    print("\n[*] Fetching AlienVault OTX feed...")
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    ips_collected = []
    page = 1

    while page <= 3:  # limit to first 3 pages for speed
        try:
            response = requests.get(
                url, headers=headers,
                params={"limit": 20, "page": page},
                timeout=15
            )
            if response.status_code != 200:
                print(f"[-] OTX API error: {response.status_code}")
                break

            data = response.json()
            pulses = data.get("results", [])
            if not pulses:
                break

            for pulse in pulses:
                for indicator in pulse.get("indicators", []):
                    if indicator.get("type") == "IPv4":
                        ips_collected.append(indicator["indicator"])

            page += 1

        except Exception as e:
            print(f"[-] OTX fetch error: {e}")
            break

    print(f"   -> OTX IPs collected: {len(ips_collected)}")
    if ips_collected:
        save_to_mongodb(ips_collected, "https://otx.alienvault.com")

if __name__ == "__main__":
    print("--- Starting Threat Intelligence Aggregator ---")
    fetch_flat_feeds()
    fetch_otx_feed()
    print("\n--- Aggregation Complete ---")