-- Create the database
CREATE DATABASE auth_service;

-- Connect to the database
\c auth_service;

-- Create the users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    full_name VARCHAR(100),
    email VARCHAR(100) UNIQUE,
    hashed_password TEXT NOT NULL,
    roles VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample data
INSERT INTO users (username, full_name, email, hashed_password, roles) VALUES
('johndoe', 'John Doe', 'johndoe@example.com', '$2b$12$e/mErQsBiknT4LpWawDPe.GyKJQn1Dxu9PczjEFSQ5f/5sDF1HMPK', 'admin'),
('janedoe', 'Jane Doe', 'janedoe@example.com', '$2b$12$M9n1X8bkXwSlP9rHgf8/m.AaHxF74jkX8WCUFBCmAaKOWE0NLHPIu', 'user');

