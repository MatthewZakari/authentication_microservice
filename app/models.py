from pydantic import BaseModel
from typing import List, Optional

class User(BaseModel):
    username: str
    full_name: str
    email: str
    hashed_password: str
    roles: List[str]

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
