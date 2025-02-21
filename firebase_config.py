import firebase_admin
from firebase_admin import credentials

if not firebase_admin._apps:  # Ensure Firebase is initialized only once
    cred = credentials.Certificate("/home/bubble/Documents/firebase_keys")
    firebase_admin.initialize_app(cred)
