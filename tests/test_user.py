from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_read_users_me():
    token = "Bearer testtoken"  # Mock token
    response = client.get("/users/me", headers={"Authorization": token})
    assert response.status_code == 200
    assert "username" in response.json()

def test_get_user_roles():
    token = "Bearer testtoken"  # Mock token
    response = client.get("/users/roles", headers={"Authorization": token})
    assert response.status_code == 200
    assert "roles" in response.json()

