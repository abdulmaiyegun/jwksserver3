import sqlite3
import time
from contextlib import contextmanager
from cryptography.hazmat.primitives import serialization
from security import generate_rsa_key, encrypt_private_key

DB_PATH = "totally_not_my_privateKeys.db"

@contextmanager
def get_db_connection():
    """
    yields a thread-safe database connection and ensures it is safely closed
    using check_same_thread=False is required for FastAPI concurrency
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    """initializes the database schema and seeds initial keys if empty"""
    with get_db_connection() as conn:
        with conn: # Handles the transaction (commit/rollback)
            conn.execute("""CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,
                exp INTEGER NOT NULL
            )""")
            conn.execute("""CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )""")
            conn.execute("""CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )""")
        seed_keys(conn)

def seed_keys(conn):
    """seeds the database with one valid and one expired encrypted RSA key if empty"""
    count = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
    if count == 0:
        now = int(time.time())
        for offset in[3600, -3600]:  # one valid, one expired
            key = generate_rsa_key()
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
            
            encrypted_key = encrypt_private_key(pem)
            with conn:
                conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", [encrypted_key, now + offset])