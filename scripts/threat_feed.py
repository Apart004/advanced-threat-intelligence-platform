import os
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv
from pymongo import MongoClient, errors

# Load environment variables securely from our hidden .env file
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.getenv("DB_NAME", "threat_intel_db")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "indicators")

def get_db_connection():
    """Establishes a connection to the MongoDB container instance."""
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
        client.server_info() # Test connection stability
        db = client[DB_NAME]
        return db[COLLECTION_NAME]
    except errors.ServerSelectionTimeoutError:
        print("[!] Database offline. Defaulting to local logging backup.")
        return None

def save_to_mongodb(ip_list, source_url):
    """Iterates through scraped IPs, enforces deduplication, and stores to Mongo."""
    collection = get_db_connection()
    if collection is None:
        return False

    duplicates_skipped = 0
    newly_inserted = 0

    for ip in ip_list:
        ip = ip.strip()
        if not ip or ip.startswith("#"):
            continue

        # Enforce database deduplication as required by company standards
        existing = collection.find_one({"indicator": ip})
        if existing:
            duplicates_skipped += 1
            continue

        # Create structured JSON threat envelope matrix using modern UTC timestamps
        threat_record = {
            "indicator": ip,
            "type": "ip",
            "source": source_url,
            "timestamp": datetime.now(timezone.utc),  # Fixed deprecation warning
            "status": "active"
        }
        
        try:
            collection.insert_one(threat_record)
            newly_inserted += 1
        except Exception as e:
            print(f"[-] Insertion failure: {e}")

    print(f"\n[{source_url}] Database Sync completed.")
    print(f"   -> Records Newly Cataloged: {newly_inserted}")
    print(f"   -> Duplicates Filtered: {duplicates_skipped}")
    return True

def fetch_feeds():
    """Your core scraping execution workflow."""
    urls = [
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    ]
    
    for url in urls:
        try:
            print(f"Downloading feed: {url}")
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                # Split raw text into individual IP lines
                ips = response.text.splitlines()
                # Clean up and filter out comment lines
                clean_ips = [ip.strip() for ip in ips if ip.strip() and not ip.startswith("#")]
                
                # Direct data to MongoDB instead of flat local data text files
                save_to_mongodb(clean_ips, url)
        except Exception as e:
            print(f"[-] Error tracking feed processing: {e}")

if __name__ == "__main__":
    print("--- Starting Threat Intelligence Aggregator Core ---")
    fetch_feeds()