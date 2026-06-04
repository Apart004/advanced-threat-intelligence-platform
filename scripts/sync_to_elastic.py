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
ES_LOGS_INDEX = "enforcement_logs"

def sync_indicators(es, collection):
    synced = 0
    skipped = 0
    for record in collection.find():
        doc_id = str(record["_id"])
        if es.exists(index=ES_INDEX, id=doc_id):
            skipped += 1
            continue
        doc = {
            "indicator":      record.get("indicator", ""),
            "type":           record.get("type", "ip"),
            "source":         record.get("source", ""),
            "status":         record.get("status", "active"),
            "risk_score":     record.get("risk_score", 5.0),
            "classification": record.get("normalization", {}).get("classification", "Unknown"),
            "confidence":     record.get("normalization", {}).get("confidence_level", "Low"),
            "blocked":        record.get("blocked", False),
            "timestamp":      record.get("timestamp", datetime.now(timezone.utc)).isoformat()
        }
        es.index(index=ES_INDEX, id=doc_id, document=doc)
        synced += 1
    print(f"[+] Indicators — Pushed: {synced} | Skipped: {skipped} | Total: {synced + skipped}")

def sync_enforcement_logs(es, collection):
    synced = 0
    skipped = 0
    for record in collection.find():
        doc_id = str(record["_id"])
        if es.exists(index=ES_LOGS_INDEX, id=doc_id):
            skipped += 1
            continue
        doc = {
            "ip":            record.get("ip", ""),
            "action":        record.get("action", "BLOCK"),
            "risk_score":    record.get("risk_score", 0),
            "source":        record.get("source", ""),
            "rolled_back":   record.get("rolled_back", False),
            "timestamp":     record.get("timestamp", datetime.now(timezone.utc)).isoformat()
        }
        es.index(index=ES_LOGS_INDEX, id=doc_id, document=doc)
        synced += 1
    print(f"[+] Enforcement logs — Pushed: {synced} | Skipped: {skipped} | Total: {synced + skipped}")

def sync():
    mongo_client = MongoClient(MONGO_URI)
    db = mongo_client[DB_NAME]
    es = Elasticsearch(ES_HOST)

    if not es.ping():
        print("[!] Cannot reach Elasticsearch. Is Docker running?")
        return

    print("[*] Syncing indicators...")
    sync_indicators(es, db[COLLECTION_NAME])

    print("[*] Syncing enforcement logs...")
    sync_enforcement_logs(es, db["enforcement_logs"])

    print("\n[*] Full sync complete.")

if __name__ == "__main__":
    sync()