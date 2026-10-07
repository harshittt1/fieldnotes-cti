from pymongo import MongoClient
from backend.config import MONGODB_URI, DATABASE_NAME


client = MongoClient(MONGODB_URI)

db = client[DATABASE_NAME]


events_collection = db["events"]
indicators_collection = db["indicators"]
malware_collection = db["malware"]
ctidigest_collection = db["ctidigest"]