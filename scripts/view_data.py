import os
from pprint import pprint
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.getenv("DB_NAME", "threat_intel_db")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "indicators")

def view_sample_indicators():
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]
    
    print("\n--- [DATABASE RECORD SAMPLE MATRIX] ---")
    
    # Grab one sample from the Abuse.ch Feodo Tracker feed
    feodo_sample = collection.find_one({"source": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"})
    if feodo_sample:
        print("\n[+] Feodo Tracker Sample Profile:")
        pprint(feodo_sample)
        
    # Grab one sample from the Emerging Threats feed
    et_sample = collection.find_one({"source": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"})
    if et_sample:
        print("\n[+] Emerging Threats Sample Profile:")
        pprint(et_sample)

if __name__ == "__main__":
    view_sample_indicators()