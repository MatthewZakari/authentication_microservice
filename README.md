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
- **Docker**: Containerized deployment for portability and easy scaling.
- **Uvicorn**: ASGI server for running the FastAPI application.

### Directory Structure

```plaintext
authentication_microservice/
├── app/
│   ├── main.py         # Main application logic
│   ├── database.py     # Database connection and operations
│   ├── models.py       # Pydantic models for request validation
│   ├── security.py     # Functions for password hashing and JWT handling
│   └── tests/          # Unit tests for endpoints and logic
├── db/
│   ├── auth_service_dump.sql  # SQL dump for setting up the database
├── Dockerfile          # Docker configuration
├── requirements.txt    # Python dependencies
└── README.md           # Project documentation

Setup Instructions
Prerequisites
Python 3.8 or higher
PostgreSQL
Docker (optional for containerization)
Installation
Clone the repository:

bash
Copy
Edit
git clone https://github.com/MatthewZakari/authentication_microservice.git
cd authentication-microservice
Install dependencies:

bash
Copy
Edit
pip install -r requirements.txt
Set up the database:

Start your PostgreSQL server.
Create a database named auth_service:
sql
Copy
Edit
CREATE DATABASE auth_service;
Import the database dump:
bash
Copy
Edit
psql -U admin -d auth_service -f db/auth_service_dump.sql
Run the application:

bash
Copy
Edit
uvicorn app.main:app --reload
Docker (Optional)
Build the Docker image:

bash
Copy
Edit
docker build -t authentication_microservice .
Run the container:

bash
Copy
Edit
docker run -p 8000:8000 authentication_microservice
Access the application at http://127.0.0.1:8000.

API Endpoints
Public Endpoints
POST /register

Description: Register a new user.
Payload:
json
Copy
Edit
{
  "username": "example",
  "full_name": "John Doe",
  "email": "example@mail.com",
  "password": "password123",
  "roles": ["user"]
}
POST /login

Description: Log in and receive a JWT.
Payload:
json
Copy
Edit
{
  "username": "example",
  "password": "password123"
}
Response:
json
Copy
Edit
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR...",
  "token_type": "bearer"
}
Protected Endpoints
GET /protected
Description: Access a resource requiring authentication.
Headers:
json
Copy
Edit
{
  "Authorization": "Bearer <JWT>"
}
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
