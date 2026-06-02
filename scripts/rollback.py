import sys
import subprocess
from datetime import datetime, timezone
from pymongo import MongoClient

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "threat_intel_db"

def get_db(collection_name):
    client = MongoClient(MONGO_URI)
    return client[DB_NAME][collection_name]

def rollback_ip(ip):
    logs = get_db("enforcement_logs")
    indicators = get_db("indicators")

    # Find the block log for this IP
    log_entry = logs.find_one({
        "ip": ip,
        "action": "BLOCK",
        "rolled_back": False
    })

    if not log_entry:
        print(f"[!] No active block found for {ip}")
        return False

    # Simulate iptables unblock (on Linux: iptables -D INPUT -s ip -j DROP)
    print(f"[*] Reversing block for {ip}...")
    print(f"    Simulating: iptables -D INPUT -s {ip} -j DROP")

    # Mark log entry as rolled back
    logs.update_one(
        {"_id": log_entry["_id"]},
        {"$set": {
            "rolled_back": True,
            "rolled_back_at": datetime.now(timezone.utc),
            "rollback_reason": "SOC analyst manual override"
        }}
    )

    # Unmark the indicator as blocked
    indicators.update_one(
        {"indicator": ip},
        {"$unset": {"blocked": "", "blocked_at": ""},
         "$set": {"status": "reviewed"}}
    )

    print(f"[+] Rollback complete for {ip}")
    print(f"    Log marked as rolled_back: True")
    print(f"    Indicator status set to: reviewed")
    return True

def show_blocked():
    logs = get_db("enforcement_logs")
    blocked = list(logs.find({"action": "BLOCK", "rolled_back": False}))
    if not blocked:
        print("[!] No active blocks found.")
        return
    print(f"\nCurrently blocked IPs ({len(blocked)}):")
    for entry in blocked:
        print(f"  - {entry['ip']} | risk_score: {entry['risk_score']} | blocked_at: {entry['timestamp']}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/rollback.py <IP_ADDRESS>")
        print("       python scripts/rollback.py --list")
        sys.exit(1)

    if sys.argv[1] == "--list":
        show_blocked()
    else:
        rollback_ip(sys.argv[1])