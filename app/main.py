from fastapi import FastAPI
from app.routes import auth, user

app = FastAPI()

""" Include routers for modular API structure"""
app.include_router(auth.router)
app.include_router(user.router, prefix="/users", tags=["users"])
