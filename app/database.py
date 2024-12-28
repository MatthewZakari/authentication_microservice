import psycopg2
from psycopg2.extras import RealDictCursor

DB_HOST = "localhost"
DB_NAME = "auth_service_db"
DB_USER = "auth_user"
DB_PASSWORD = "auth_password"

conn = psycopg2.connect(
    dbname="auth_service",
    user="admin",
    password="password123",
    host="localhost",
    port="5432"
)


def get_user(username: str):
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        return cursor.fetchone()

def add_user(user):
    with conn.cursor() as cursor:
        cursor.execute(
            "INSERT INTO users (username, full_name, email, hashed_password, roles) VALUES (%s, %s, %s, %s, %s)",
            (user.username, user.full_name, user.email, user.hashed_password, user.roles),
        )
        conn.commit()
