from pymongo import MongoClient
from dotenv import load_dotenv
import os

# Load .env file
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

# Connect to Atlas
client = MongoClient(MONGO_URI)

# Database select
db = client["soneri_db"]

# Collection select
users = db["users"]

# Insert a test user
res = users.insert_one({"username": "junaid", "email": "junaid@example.com"})
print("Inserted ID:", res.inserted_id)

# Find the inserted user
doc = users.find_one({"username": "junaid"})
print("Found user:", doc)
