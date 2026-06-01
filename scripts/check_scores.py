from pymongo import MongoClient

client = MongoClient('mongodb://localhost:27017/')
col = client['threat_intel_db']['indicators']

total = col.count_documents({})
high_risk = col.count_documents({"risk_score": {"$gte": 8.0}})
has_blocked = col.count_documents({"blocked": True})

print(f"Total indicators: {total}")
print(f"High risk (score >= 8): {high_risk}")
print(f"Already marked blocked: {has_blocked}")