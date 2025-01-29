# Authentication Microservice

This project is a lightweight and scalable authentication microservice built using Python's FastAPI framework. It provides secure token-based authentication with JWT, allowing users to register, log in, and manage access to protected resources. Designed to be easily integrated into larger applications, this microservice follows best practices for secure authentication and extensibility.

## Features

- **User Registration**: Securely register users with hashed passwords using `bcrypt`.
- **User Login**: Authenticate users and issue JWTs for session management.
- **Token-Based Authentication**: Secure API access with JSON Web Tokens (JWT).
- **Role-Based Access Control (RBAC)**: Restrict access to certain endpoints based on user roles.
- **Built-in Security**: Follows best practices like hashing sensitive data and secure token generation.
- **Scalable Design**: Suitable for small to medium-sized applications and can be extended for enterprise systems.

## Project Architecture

- **FastAPI**: Framework for building APIs with Python.
- **PostgreSQL**: Relational database for storing user information.
- **bcrypt**: Library for hashing and verifying passwords.
- **JWT (PyJWT)**: Token generation and validation for secure user sessions.
- **Uvicorn**: ASGI server for running the FastAPI application.

### Directory Structure


authentication_microservice/
├── app/
│   ├── main.py         
│   ├── database.py     
│   ├── __init__.py
│
├── config/
│   ├── settings.py 
│
├── db/
│   ├── auth_service_dump.sql  
├── requirements.txt    
└── README.md           


Setup Instructions
Prerequisites
Python 3.8 or higher
PostgreSQL

Installation
Clone the repository:
git clone https://github.com/MatthewZakari/authentication_microservice.git
cd authentication-microservice

Install dependencies:
pip install -r requirements.txt (some requirements was installed while debugging and might not have been added here, please do well to install them to avoid errors)

Set up the database:
sudo service postgresql start

Create a database named auth_service:
sql
CREATE DATABASE auth_service;
Import the database dump:
psql -U admin -d auth_service -f db/auth_service_dump.sql

Run the application:
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
Access the application at http://127.0.0.1:8000.

API Endpoints:
Public Endpoints
Registration: Register a new user by sending a POST request to the /register/ endpoint:

curl -X POST \
-H "Content-Type: application/json" \
-d '{"username": "newuser", "full_name": "New User", "email": "newuser@example.com", "password": "securepassword", "roles": ["user"]}' \
http://localhost:8000/register/

Upon successful registration, a confirmation message is returned.

Login: Log in with the registered credentials using the /login endpoint:

curl -X POST \
-H "Content-Type: application/json" \
-d '{"username": "linus", "password": "securepassword"}' \
http://localhost:8000/login

This returns a JWT token.

Protected Route: Access a protected route, /protected-route/, using the JWT token:

curl -X GET \
-H "Authorization: Bearer "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsaW51cyIsImV4cCI6MTczNzcwMjI1MH0.Swn-dkMkHF38eKqPayqnch9gFJxSVSsz9lP7rt3ZjOI"" \
http://localhost:8000/protected-route/

Replace <your_access_token> with the token received from the login response. If the token is valid, access is granted; otherwise, an error is returned.

Error Handling: Demonstrate what happens with an invalid or expired token:

curl -X GET \
-H "Authorization: Bearer invalid_or_expired_token" \
http://localhost:8000/protected-route/

The system responds with an appropriate error message, ensuring secure access control."

Challenges and Improvements
Challenges:

Initial setup of token-based authentication.
Ensuring secure password hashing and storage.
Managing role-based access control effectively.
Areas for Improvement:

Add support for third-party identity providers (OAuth2/OpenID Connect).
Enhance unit tests for edge cases.
Integrate CI/CD pipelines for automated deployment.
Lessons Learned
Understanding the importance of secure password management and hashing.
Implementing and validating JWTs for secure API access.
The significance of scalable design and modular architecture in microservices.
Next Steps
Add multi-factor authentication (MFA) for improved security.
Implement logging and monitoring to track API usage.
Integrate with third-party identity providers for federated authentication.
Conclusion
This Authentication Microservice is a foundational implementation showcasing the principles of secure authentication in a microservice architecture. With its modular and scalable design, it serves as a robust solution for managing user authentication and access control in various applications.

For questions or contributions, feel free to reach out or open an issue on the repository

This `README.md` file provides a professional overview of the project, guiding users and developers through setup, usage, and project details.
