-- Books table
CREATE TABLE books (
    id SERIAL PRIMARY KEY,
    title VARCHAR(150) NOT NULL,
    author VARCHAR(100) NOT NULL,
    available BOOLEAN DEFAULT TRUE
);

-- Users table (business users, not Keycloak users)
CREATE TABLE library_users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL
);

-- Borrowings table
CREATE TABLE borrowings (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES library_users(id),
    book_id INT REFERENCES books(id),
    borrow_date DATE DEFAULT CURRENT_DATE,
    return_date DATE
);
