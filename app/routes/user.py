from fastapi import APIRouter, Depends
from app.models import User
from app.utils import get_current_user

router = APIRouter()

@router.get("/users/me", response_model=User)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.get("/users/roles")
def get_user_roles(current_user: User = Depends(get_current_user)):
    return {"roles": current_user.roles}

