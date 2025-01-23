from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
#from app.utils import hash_password
from app.database import get_db_connection
import os
import bcrypt

# Initialize FastAPI app
app = FastAPI()

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Environment variables for security
SECRET_KEY = os.getenv("SECRET_KEY", "your_default_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

# Pydantic models
class RegisterRequest(BaseModel):
    username: str
    full_name: str
    email: EmailStr
    password: str
    roles: List[str]

class LoginRequest(BaseModel):
    username: str
    password: str

class UserDB(BaseModel):
    username: str
    full_name: str
    email: EmailStr
    hashed_password: str
    roles: List[str]

class UserResponse(BaseModel):
    username: str
    full_name: str
    email: EmailStr
    roles: List[str]

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def get_current_user(token: str = Depends(oauth2_scheme)) -> UserDB:
    username = decode_token(token)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT username, full_name, email, hashed_password, roles FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return UserDB(
            username=user['username'],
            full_name=user['full_name'],
            email=user['email'],
            hashed_password=user['hashed_password'],
            roles=user['roles'].split(",")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching user: {str(e)}")
    finally:
        cursor.close()
        conn.close()

# Endpoints
@app.post("/register/")
def register_user(request: RegisterRequest):
    hashed_password = hash_password(request.password)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, full_name, email, hashed_password, roles) VALUES (%s, %s, %s, %s, %s)",
            (request.username, request.full_name, request.email, hashed_password, ",".join(request.roles))
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=f"Error saving user: {str(e)}")
    finally:
        cursor.close()
        conn.close()
    return {"message": "User registered successfully!"}

@app.post("/login")
def login(request: LoginRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT username, full_name, email, hashed_password, roles FROM users WHERE username = %s", (request.username,))
        user = cursor.fetchone()
        if not user or not verify_password(request.password, user['hashed_password']):
            raise HTTPException(status_code=401, detail="Invalid username or password")
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user['username']}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during login: {str(e)}")
    finally:
        cursor.close()
        conn.close()

@app.get("/users/me", response_model=UserResponse)
def read_users_me(current_user: UserDB = Depends(get_current_user)):
    return current_user

@app.get("/users")
def get_all_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT username, full_name, email, roles FROM users")
        users = cursor.fetchall()
        return [
            {
                "username": user['username'],
                "full_name": user['full_name'],
                "email": user['email'],
                "roles": user['roles'].split(",")
            } for user in users
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching users: {str(e)}")
    finally:
        cursor.close()
        conn.close()

@app.get("/users/{username}")
def get_user_by_username(username: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT username, full_name, email, roles FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return {
            "username": user['username'],
            "full_name": user['full_name'],
            "email": user['email'],
            "roles": user['roles'].split(",")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching user: {str(e)}")
    finally:
        cursor.close()
        conn.close()

@app.get("/protected-route/")
def protected_route(current_user: UserDB = Depends(get_current_user)):
    return {"message": f"Access granted to {current_user.username}"}

