import os
from fastapi import FastAPI, HTTPException
from pymongo import MongoClient
from dotenv import load_dotenv

# Load configurations
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.getenv("DB_NAME", "threat_intel_db")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "indicators")

# Initialize FastAPI App
app = FastAPI(
    title="Advanced Threat Intelligence Platform Gateway",
    version="1.0.0",
    description="Production-grade REST API for querying normalized threat indicators and firewall feeds."
)

# Database Connection Helper
def get_db_collection():
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    return db[COLLECTION_NAME]

@app.get("/")
def read_root():
    """Health check endpoint to ensure the API gateway is alive."""
    return {
        "status": "online",
        "platform": "Advanced Threat Intelligence Platform",
        "engine_version": "1.0.0"
    }