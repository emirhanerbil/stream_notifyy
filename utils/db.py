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


def get_streamers_collection():
    db = get_database()
    return db["streamers"]

async def get_streamers(username,streamer_collection):
    streamer_list = await streamer_collection.find_one({"username": username})
    return streamer_list["streamers"]


async def remove_streamer(username,streamer_collection,streamer_name):
    removed_streamer = await streamer_collection.update_one({"username": username},{"$pull": {"streamers": streamer_name}})
    return removed_streamer

async def add_streamer(username,streamer_collection,streamer_name):
    user = await streamer_collection.find_one({"username": username})
    streamers = user["streamers"]
    if streamer_name in streamers:
        return True
    
    added_streamer = await streamer_collection.update_one({"username": username},{"$push": {"streamers": streamer_name}})
    return False
