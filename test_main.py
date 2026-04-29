import pytest
from fastapi.testclient import TestClient
import uuid
from main import app

# import the init function
from database import init_db

# manually build the database tables for the test environment
init_db()

# start the test client
client = TestClient(app)

def test_jwks_endpoint():
    """test that the jwks endpoint returns a 200 OK and a list of keys"""
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert isinstance(data["keys"], list)

def test_register_user():
    """test user registration returns a generated password"""
    random_user = f"test_user_{uuid.uuid4()}"
    response = client.post("/register", json={
        "username": random_user,
        "email": f"{random_user}@example.com"
    })
    
    assert response.status_code == 201
    assert "password" in response.json()

def test_auth_endpoint():
    """test standard authentication returns a valid token"""
    response = client.post("/auth", json={"username": "fake_user"})
    assert response.status_code == 200
    assert "token" in response.json()

def test_auth_expired():
    """test expired authentication flag returns a token"""
    response = client.post("/auth?expired=true", json={"username": "fake_user"})
    assert response.status_code == 200
    assert "token" in response.json()