# filepath: /Users/prateek/Desktop/auth-api/main.py
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import firebase_admin
import os
import base64
from dotenv import load_dotenv
from firebase_admin import credentials, auth
import requests
import json

# Load environment variables from .env file
load_dotenv()


firebase_creds_b64 = os.getenv("FIREBASE_CREDENTIALS")

if not firebase_creds_b64:
    raise ValueError("FIREBASE_CREDENTIALS environment variable is not set")

firebase_creds_str = base64.b64decode(firebase_creds_b64).decode("utf-8")

# Convert JSON string to dictionary
firebase_creds = json.loads(firebase_creds_str)

# Initialize Firebase Admin SDK
cred = credentials.Certificate(firebase_creds)
firebase_admin.initialize_app(cred)



app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Welcome to the FastAPI Firebase Auth backend!"}

# Signup model
class SignupRequest(BaseModel):
    email: str
    password: str

@app.post("/signup")
def signup(request: SignupRequest):
    try:
        user = auth.create_user(email=request.email, password=request.password)
        return {"message": "User created successfully", "uid": user.uid}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Login model
class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/login")
def login(request: LoginRequest):
    url = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=AIzaSyCirVLQPuq8gRDr0orVMIBJC1i8jhbV4bI"
    payload = {
        "email": request.email,
        "password": request.password,
        "returnSecureToken": True
    }
    response = requests.post(url, json=payload)

    if response.status_code == 200:
        return response.json()
    else:
        raise HTTPException(status_code=400, detail=response.json())

# Protected user route
from fastapi import Depends

def get_current_user(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")

    token = authorization.split("Bearer ")[-1]  # Extract token

    try:
        decoded_token = auth.verify_id_token(token)
        return decoded_token
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/user")
def get_user(user=Depends(get_current_user)):
    return {"user": user}