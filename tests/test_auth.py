from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_login_for_access_token():
    response = client.post(
        "/token",
        data={"username": "testuser", "password": "testpassword"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
