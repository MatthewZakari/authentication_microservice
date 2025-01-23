from fastapi import FastAPI, HTTPException, APIRouter, Depends
from pydantic import BaseModel, EmailStr
from typing import List
from app.utils import hash_password, get_current_user
from app.database import get_db_connection
from app.models import User

# Declare router
router = APIRouter()

# Define a Pydantic model for the request body
class RegisterRequest(BaseModel):
    username: str
    full_name: str
    email: EmailStr
    password: str
    roles: List[str]

@router.get("/users/me", response_model=User)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.get("/users/roles")
def get_user_roles(current_user: User = Depends(get_current_user)):
    return {"roles": current_user.roles}

@router.post("/register")
def register_user(request: RegisterRequest):
    hashed_password = hash_password(request.password)
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (username, full_name, email, hashed_password, roles) VALUES (%s, %s, %s, %s, %s)",
            (request.username, request.full_name, request.email, hashed_password, ",".join(request.roles)),
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=f"Error saving user: {str(e)}")
    finally:
        cursor.close()
        conn.close()

    return {"message": "User registered successfully!"}

@router.get("/users")
def get_all_users():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM users")
        rows = cursor.fetchall()

        users = [
            {"id": row[0], "username": row[1], "full_name": row[2], "email": row[3], "roles": row[5].split(",")}
            for row in rows
        ]
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching users: {str(e)}")
    finally:
        cursor.close()
        conn.close()

@router.get("/users/{username}")
def get_user_by_username(username: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return {
            "id": user[0],
            "username": user[1],
            "full_name": user[2],
            "email": user[3],
            "roles": user[5].split(","),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching user: {str(e)}")
    finally:
        cursor.close()
        conn.close()

