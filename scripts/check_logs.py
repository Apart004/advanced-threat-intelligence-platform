from pymongo import MongoClient
from pprint import pprint

client = MongoClient('mongodb://localhost:27017/')
logs = client['threat_intel_db']['enforcement_logs']

print(f'Total enforcement logs: {logs.count_documents({})}')
for log in logs.find():
    pprint(log)
    print()