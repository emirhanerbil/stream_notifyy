from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os

load_dotenv()

def get_database():
    uri = os.environ.get("URI")
    client = AsyncIOMotorClient(uri)
    return client['users']

def get_users_collection():
    db = get_database()
    return db['user_info']



