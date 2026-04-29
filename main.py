import time
import uuid
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, Query
import jwt
from cryptography.hazmat.primitives import serialization

# import from modules
from database import init_db, get_db_connection
from security import decrypt_private_key, private_pem_to_jwk, ph
from models import RegisterRequest, AuthRequest

@asynccontextmanager
async def lifespan(app: FastAPI):
    """lifecycle manager to initialize the database upon server startup"""
    init_db()
    yield

app = FastAPI(title="JWKS Server", lifespan=lifespan)

@app.get("/.well-known/jwks.json")
def jwks():
    """returns all unexpired public keys in standard jwks format"""
    now = int(time.time())
    keys =[]
    
    try:
        with get_db_connection() as conn:
            rows = conn.execute("SELECT * FROM keys WHERE exp > ?", [now]).fetchall()
            
        for row in rows:
            try:
                pem = decrypt_private_key(row["key"])
                jwk_dict = private_pem_to_jwk(pem, row["kid"])
                keys.append(jwk_dict)
            except ValueError as ve:
                print(f"skipping key {row['kid']} due to decryption/formatting error: {ve}")
                
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"database error: {e}")
        
    return {"keys": keys}

@app.post("/auth")
def auth(request: Request, body: AuthRequest = None, expired: bool = Query(False)):
    """authenticates a user, logs the request and returns a signed jwt"""
    ip = request.client.host if request.client else "127.0.0.1"
    now = int(time.time())
    user_id = None
    username = body.username if body else None

    try:
        with get_db_connection() as conn:
            with conn:  # Transaction block
                # fetch appropriate key
                if expired:
                    row = conn.execute("SELECT * FROM keys WHERE exp < ? LIMIT 1", [now]).fetchone()
                else:
                    row = conn.execute("SELECT * FROM keys WHERE exp > ? LIMIT 1", [now]).fetchone()

                if not row:
                    raise HTTPException(status_code=500, detail="no suitable key found in database")

                try:
                    pem = decrypt_private_key(row["key"])
                except ValueError:
                    raise HTTPException(status_code=500, detail="key decryption failed due to invalid format")

                # check user and update last_login
                if username:
                    user = conn.execute("SELECT id FROM users WHERE username = ?", [username]).fetchone()
                    if user:
                        user_id = user["id"]
                        conn.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",[user_id])

                # log authentication request
                conn.execute(
                    "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", 
                    [ip, user_id]
                )
                kid = row["kid"]
    except sqlite3.Error as db_err:
        raise HTTPException(status_code=500, detail=f"Database interaction failed: {db_err}")

    # sign jwt
    payload = {
        "sub": username or "anonymous",
        "iat": now,
        "exp": now + (-1 if expired else 3600),
    }

    try:
        private_key = serialization.load_pem_private_key(pem.encode(), password=None)
        token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": str(kid)})
    except (ValueError, TypeError) as sign_err:
        raise HTTPException(status_code=500, detail=f"failed to sign token: {sign_err}")

    return {"token": token}

@app.post("/register", status_code=201)
def register(body: RegisterRequest):
    """registers a new user, generating a UUIDv4 password and hashing it via Argon2"""
    password = str(uuid.uuid4())
    hashed = ph.hash(password)

    try:
        with get_db_connection() as conn:
            with conn:  
                conn.execute(
                    "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",[body.username, hashed, body.email]
                )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="username or email already exists")
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"database error occurred: {e}")

    return {"password": password}