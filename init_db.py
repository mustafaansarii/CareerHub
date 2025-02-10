import sqlite3
import os

# Define the database file path
DATABASE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db")

def create_tables():
    with sqlite3.connect(DATABASE_FILE) as conn:
        cur = conn.cursor()

        # Create users table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')

        # Create resumes table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS resumes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                imglink TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                hreflink TEXT NOT NULL,
                pick TEXT NOT NULL,
                authorname TEXT NOT NULL
            )
        ''')

        # Create roadmaps table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS roadmaps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fieldname TEXT NOT NULL,
                roadmaplink TEXT NOT NULL
            )
        ''')

        # Create DSA questions table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS dsa_questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                topic TEXT NOT NULL,
                title TEXT NOT NULL,
                qsnlink TEXT NOT NULL
            )
        ''')

        conn.commit()
        print("Database initialized successfully!")

if __name__ == "__main__":
    create_tables()
