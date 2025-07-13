DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS grievances;
DROP TABLE IF EXISTS good_boy_moments;
DROP TABLE IF EXISTS bad_boy_moments;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    fullname TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
);

CREATE TABLE grievances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    message TEXT NOT NULL CHECK(length(message) <= 2000),
    timestamp TEXT NOT NULL
);

CREATE TABLE good_boy_moments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE TABLE bad_boy_moments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

INSERT INTO users (username, fullname, password, role) VALUES ('becca23.11', 'Becca', 'beccahatessamar29', 'superuser'); 