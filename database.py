from pymongo import MongoClient
import datetime

client = MongoClient("mongodb://localhost:27017/")
db = client["cloud_logs"]
collection = db["logs"]
verification_collection = db["verification_history"]

def insert_log(log):
    collection.insert_one(log)

def get_logs():
    return list(collection.find().sort("timestamp"))

def clear_logs():
    collection.delete_many({})

def insert_verification_record(tampered_index):
    record = {
        "timestamp": str(datetime.datetime.now()),
        "total_logs": collection.count_documents({}),
        "status": "tampered" if tampered_index != -1 else "secure",
        "tampered_index": tampered_index
    }
    verification_collection.insert_one(record)

def get_verification_history(limit=20):
    return list(verification_collection.find().sort("timestamp", -1).limit(limit))

def clear_verification_history():
    verification_collection.delete_many({})