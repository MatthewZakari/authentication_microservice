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
    """Schema for user registration request."""
    username: str
    full_name: str
    email: EmailStr
    password: str
    roles: List[str]

class LoginRequest(BaseModel):
    """Schema for user login request."""
    username: str
    password: str

class UserDB(BaseModel):
    """Schema for representing a user stored in the database."""
    username: str
    full_name: str
    email: EmailStr
    hashed_password: str
    roles: List[str]

class UserResponse(BaseModel):
    """Schema for user data returned in API responses."""
    username: str
    full_name: str
    email: EmailStr
    roles: List[str]

class Token(BaseModel):
    """Schema for the access token response."""
    access_token: str
    token_type: str

class TokenData(BaseModel):
    """Schema for data encoded in the token."""
    username: Optional[str] = None

# Utility functions
def verify_password(plain_password, hashed_password):
    """Verify a plain-text password against a hashed password.

    Args:
        plain_password (str): The plain-text password.
        hashed_password (str): The hashed password.

    Returns:
        bool: True if the passwords match, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password: str) -> str:
    """Hash a password using bcrypt.

    Args:
        password (str): The plain-text password.

    Returns:
        str: The hashed password.
    """
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JSON Web Token (JWT).

    Args:
        data (dict): The data to encode in the token.
        expires_delta (timedelta, optional): The token's expiration time.

    Returns:
        str: The encoded JWT.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    """Decode and validate a JWT.

    Args:
        token (str): The JWT to decode.

    Returns:
        str: The username from the token.

    Raises:
        HTTPException: If the token is invalid or expired.
    """
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
    """Retrieve the current user from the token.

    Args:
        token (str): The JWT from the Authorization header.

    Returns:
        UserDB: The authenticated user's data.

    Raises:
        HTTPException: If the user is not found or the token is invalid.
    """
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
    """Register a new user.

    Args:
        request (RegisterRequest): The registration details.

    Returns:
        dict: A success message.

    Raises:
        HTTPException: If there is an error saving the user.
    """
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

    print("\n")
    return {"message": "User registered successfully!"}

@app.post("/login")
def login(request: LoginRequest):
    """Authenticate a user and generate a JWT.

    Args:
        request (LoginRequest): The login details.

    Returns:
        dict: The access token and its type.

    Raises:
        HTTPException: If the username or password is invalid.
    """
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
        print("\n")
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during login: {str(e)}")
    finally:
        cursor.close()
        conn.close()

@app.get("/users/me", response_model=UserResponse)
def read_users_me(current_user: UserDB = Depends(get_current_user)):
    """Get the current authenticated user's details.

    Args:
        current_user (UserDB): The authenticated user.

    Returns:
        UserResponse: The user's details.
    """
    return current_user

@app.get("/users")
def get_all_users():
    """Retrieve a list of all users.

    Returns:
        list: A list of user details.

    Raises:
        HTTPException: If there is an error fetching users.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT username, full_name, email, roles FROM users")
        users = cursor.fetchall()
        print("\n")
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
    """Retrieve a user's details by username.

    Args:
        username (str): The username to search for.

    Returns:
        dict: The user's details.

    Raises:
        HTTPException: If the user is not found or there is an error fetching the user.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT username, full_name, email, roles FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        print("\n")
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
    """Access a protected route that requires authentication.

    Args:
        current_user (UserDB): The authenticated user.

    Returns:
        dict: A success message with the username.
    """
    print("\n")
    return {"message": f"Access granted to {current_user.username}"}

