from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class UserRegistration(BaseModel):
    username: str
    public_key: bytes
    encrypted_envelope: bytes


class UserLogin(BaseModel):
    username: str


@app.post("/register")
async def register_user(user: UserRegistration):
    return {"message": "User registered successfully"}


@app.post("/login")
async def login_user(user: UserLogin):
    return {"message": "User logged in successfully"}
