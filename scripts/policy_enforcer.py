import os
import subprocess
from datetime import datetime, timezone
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://tip_mongodb:27017/")
DB_NAME = os.getenv("DB_NAME", "threat_intel_db")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "indicators")
RISK_THRESHOLD = float(os.getenv("RISK_THRESHOLD", "8.0"))

def get_db(collection_name):
    client = MongoClient(MONGO_URI)
    return client[DB_NAME][collection_name]

def block_ip(ip):
    try:
        result = subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"[+] BLOCKED: {ip}")
            return True
        else:
            print(f"[-] iptables error for {ip}: {result.stderr}")
            return False
    except Exception as e:
        print(f"[-] Failed to block {ip}: {e}")
        return False

def enforce():
    indicators = get_db(COLLECTION_NAME)
    logs = get_db("enforcement_logs")

    high_risk = indicators.find({
        "risk_score": {"$gte": RISK_THRESHOLD},
        "type": "ip",
        "status": "active",
        "blocked": {"$exists": False}
    })

    blocked_count = 0

    for record in high_risk:
        ip = record.get("indicator")
        if not ip:
            continue

        success = block_ip(ip)

        if success:
            indicators.update_one(
                {"_id": record["_id"]},
                {"$set": {"blocked": True, "blocked_at": datetime.now(timezone.utc)}}
            )
            logs.insert_one({
                "ip": ip,
                "action": "BLOCK",
                "risk_score": record.get("risk_score"),
                "source": record.get("source"),
                "timestamp": datetime.now(timezone.utc),
                "rolled_back": False,
                "indicator_id": record["_id"]
            })
            blocked_count += 1

    print(f"\n[*] Enforcement complete. IPs blocked this run: {blocked_count}")

if __name__ == "__main__":
    print("--- Policy Enforcer Starting ---")
    print(f"    Risk threshold: {RISK_THRESHOLD}")
    enforce()