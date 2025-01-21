from fastapi import FastAPI, HTTPException, APIRouter, Depends
from pydantic import BaseModel, EmailStr
from typing import List
from app.utils import hash_password, get_current_user
from app.database import get_db_connection
from app.models import User

app = FastAPI()
router = APIRouter()

""" Define a Pydantic model for the request body """
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

@router.post("/register/")
def register_user(request: RegisterRequest):
    """ Hash the password """
    hashed_password = hash_password(request.password)

    """ Get database connection """
    conn = get_db_connection()
    cursor = conn.cursor()

    """ Insert user into the database """
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

app.include_router(router)

