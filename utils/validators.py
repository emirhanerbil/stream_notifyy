import re
from fastapi import HTTPException


def is_password_valid(password: str):
    if len(password) < 8 or len(password) > 20:
        return False
    return True


async def is_username_existed(users_collection,username):
    existing_user = await users_collection.find_one({"username": username})
    if existing_user:
        return True
    return False

async def is_email_existed(users_collection,email):
    existing_email = await users_collection.find_one({"mail": email})
    if existing_email:
        return True
    return False