CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(50),
  role VARCHAR(20)
);

CREATE TABLE resources (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100)
);

CREATE TABLE permissions (
  id SERIAL PRIMARY KEY,
  user_id INT REFERENCES users(id),
  resource_id INT REFERENCES resources(id)
);
