from typing import Optional
from jose import jwt, JWTError
from datetime import datetime, timedelta
import bcrypt

""" Constants for JWT """
SECRET_KEY = "your_secret_key"  # Replace with a secure, random key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def hash_password(password: str) -> str:
    """
    Hashes a plaintext password using bcrypt.

    Args:
        password (str): Plaintext password.

    Returns:
        str: Hashed password.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verifies a password against its hashed version.

    Args:
        password (str): Plaintext password.
        hashed_password (str): Hashed password.

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates a JSON Web Token (JWT) for a user.

    Args:
        data (dict): Data to include in the token.
        expires_delta (timedelta, optional): Expiration time delta.

    Returns:
        str: Encoded JWT token.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str) -> dict:
    """
    Decodes a JWT token to retrieve the current user's information.

    Args:
        token (str): JWT token.

    Returns:
        dict: Decoded payload containing user information.

    Raises:
        ValueError: If the token is invalid or missing required data.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise ValueError("Invalid token payload: 'sub' is missing.")
        return {"username": username}
    except JWTError as e:
        raise ValueError("Invalid token.") from e

