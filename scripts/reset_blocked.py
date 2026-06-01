from pymongo import MongoClient

client = MongoClient('mongodb://localhost:27017/')
col = client['threat_intel_db']['indicators']

result = col.update_many(
    {"blocked": True},
    {"$unset": {"blocked": "", "blocked_at": ""}}
)
print(f"Reset {result.modified_count} blocked indicators")