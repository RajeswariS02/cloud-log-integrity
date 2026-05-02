from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")
db = client["cloud_logs"]
collection = db["logs"]

def insert_log(log):
    collection.insert_one(log)

def get_logs():
    return list(collection.find().sort("timestamp"))

def clear_logs():
    collection.delete_many({})