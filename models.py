from pydantic import BaseModel, EmailStr

class RegisterRequest(BaseModel):
    """schema for user registration requests"""
    username: str
    email: EmailStr | None = None

class AuthRequest(BaseModel):
    """schema for authentication requests"""
    username: str | None = None