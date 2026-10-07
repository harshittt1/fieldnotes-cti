import os

from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.server_api import ServerApi


load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")

if not MONGODB_URI:
    raise ValueError("MONGODB_URI is missing from .env")


client = MongoClient(
    MONGODB_URI,
    server_api=ServerApi(
        version="1",
        strict=True,
        deprecation_errors=True
    )
)

try:
    client.admin.command("ping")
    print("MongoDB Atlas connection successful!")

finally:
    client.close()