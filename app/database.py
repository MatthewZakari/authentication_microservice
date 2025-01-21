import os
import psycopg2
from psycopg2.extras import RealDictCursor

""" Load database credentials from environment variables """
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "auth_service")
DB_USER = os.getenv("DB_USER", "admin")
DB_PASSWORD = os.getenv("DB_PASSWORD", "@Zakari2196")
DB_PORT = os.getenv("DB_PORT", "5432")

def get_db_connection():
    """
    Establish and return a new database connection.
    Uses RealDictCursor to return query results as dictionaries.
    """
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT,
            cursor_factory=RealDictCursor,
        )
        return conn
    except psycopg2.Error as e:
        print(f"Database connection error: {e}")
        raise

def get_user(username: str):
    """
    Fetch a user from the database by username.
    :param username: The username to search for.
    :return: User record as a dictionary or None if not found.
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                return cursor.fetchone()
    except Exception as e:
        print(f"Error fetching user: {e}")
        raise

def add_user(user):
    """
    Add a new user to the database.
    :param user: A user object with attributes: username, full_name, email, hashed_password, roles.
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO users (username, full_name, email, hashed_password, roles)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (user.username, user.full_name, user.email, user.hashed_password, user.roles),
                )
                conn.commit()
    except Exception as e:
        print(f"Error adding user: {e}")
        raise

