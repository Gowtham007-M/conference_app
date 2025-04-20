-- Drop tables if they exist
DROP TABLE IF EXISTS registrations;
DROP TABLE IF EXISTS conferences;
DROP TABLE IF EXISTS users;

-- Create the 'users' table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('organizer', 'attendee'))
);

-- Create the 'conferences' table
CREATE TABLE conferences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    date TEXT NOT NULL,
    organizer_id INTEGER,
    FOREIGN KEY (organizer_id) REFERENCES users(id)
);

-- Create the 'registrations' table
CREATE TABLE registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    conference_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (conference_id) REFERENCES conferences(id),
    UNIQUE (user_id, conference_id)  -- Prevent duplicate registrations
);
