import os
from datetime import datetime, timezone
from dotenv import load_dotenv
from pymongo import MongoClient
from elasticsearch import Elasticsearch

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.getenv("DB_NAME", "threat_intel_db")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "indicators")
ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_INDEX = os.getenv("ES_INDEX", "threat_indicators")

def sync():
    # Connect to MongoDB
    mongo_client = MongoClient(MONGO_URI)
    collection = mongo_client[DB_NAME][COLLECTION_NAME]

    # Connect to Elasticsearch
    es = Elasticsearch(ES_HOST)
    if not es.ping():
        print("[!] Cannot reach Elasticsearch. Is Docker running?")
        return

    print(f"[*] Starting sync to Elasticsearch index: {ES_INDEX}")

    synced = 0
    skipped = 0

    for record in collection.find():
        doc_id = str(record["_id"])

        # Skip if already in Elasticsearch
        if es.exists(index=ES_INDEX, id=doc_id):
            skipped += 1
            continue

        # Build clean document (ES can't store MongoDB _id object)
        doc = {
            "indicator":       record.get("indicator", ""),
            "type":            record.get("type", "ip"),
            "source":          record.get("source", ""),
            "status":          record.get("status", "active"),
            "risk_score":      record.get("risk_score", 5.0),
            "classification":  record.get("normalization", {}).get("classification", "Unknown"),
            "confidence":      record.get("normalization", {}).get("confidence_level", "Low"),
            "timestamp":       record.get("timestamp", datetime.now(timezone.utc)).isoformat()
        }

        es.index(index=ES_INDEX, id=doc_id, document=doc)
        synced += 1

    print(f"[+] Sync complete.")
    print(f"   -> Pushed to Elasticsearch: {synced}")
    print(f"   -> Already existed (skipped): {skipped}")
    print(f"   -> Total in index: {synced + skipped}")

if __name__ == "__main__":
    sync()