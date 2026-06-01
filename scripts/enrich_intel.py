import os
from datetime import datetime, timezone
from dotenv import load_dotenv
from pymongo import MongoClient

# Load configuration settings
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.getenv("DB_NAME", "threat_intel_db")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "indicators")

# Core Evaluation Rules: Reliability weights assigned to OSINT sources
SOURCE_WEIGHTS = {
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt": 0.9,
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt": 0.6,
    "https://otx.alienvault.com": 0.8
}

def calculate_risk_score(source_url, malicious_count=0):
    weight = SOURCE_WEIGHTS.get(source_url, 0.5)
    # Boost score if VirusTotal confirms malicious detections
    bonus = min(malicious_count * 0.3, 3.0)
    return round(min((weight * 10.0) + bonus, 10.0), 1)

def enrich_and_normalize():
    """Extracts raw unnormalized indicators, applies scoring, and updates documents."""
    try:
        client = MongoClient(MONGO_URI)
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]
    except Exception as e:
        print(f"[-] Database connectivity error: {e}")
        return

    # Find indicators that haven't been processed yet by looking for missing score field
    unprocessed_indicators = collection.find({"risk_score": {"$exists": False}})
    
    count = 0
    print("[*] Initiating Risk-Scoring Optimization Engine...")

    for record in unprocessed_indicators:
        record_id = record["_id"]
        source = record.get("source", "Unknown")
        
        # Calculate dynamic matrix scores
        risk_score = calculate_risk_score(source)
        
        # Determine threat classification profiles based on source
        if "feodotracker" in source.lower():
            classification = "Botnet Command & Control"
            confidence = "High"
        else:
            classification = "Compromised Host / Scanner"
            confidence = "Medium"

        # Formulate update payload modifications
        enrichment_payload = {
            "$set": {
                "risk_score": risk_score,
                "normalization": {
                    "classification": classification,
                    "confidence_level": confidence,
                    "engine_version": "1.0.0",
                    "evaluated_at": datetime.now(timezone.utc)
                }
            }
        }

        # Commit update packet safely to database document target
        collection.update_one({"_id": record_id}, enrichment_payload)
        count += 1

    print(f"[+] Enrichment process finalized. Successfully normalized {count} threat profiles.")

if __name__ == "__main__":
    enrich_and_normalize()