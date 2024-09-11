from pydantic import BaseModel, EmailStr
from typing import Optional

class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserInDB(BaseModel):
    email: EmailStr
    username: str
    hashed_password: str

class Streamers(BaseModel):
    username: str
    streamers : list