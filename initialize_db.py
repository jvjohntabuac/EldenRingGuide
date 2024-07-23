import sqlite3

def initialize_database():
    conn = sqlite3.connect('user_accounts.db')  
    c = conn.cursor()

    # Create or update Users table
    c.execute('''CREATE TABLE IF NOT EXISTS Users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL
                );''')

    # Create or update Posts table
    c.execute('''CREATE TABLE IF NOT EXISTS Posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    author_id INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (author_id) REFERENCES Users(id)
                );''')

    # Add image_url column to Posts table if it does not exist
    try:
        c.execute('ALTER TABLE Posts ADD COLUMN image_url TEXT;')
        print("Added 'image_url' column to 'Posts' table.")
    except sqlite3.OperationalError:
        print("'image_url' column already exists in 'Posts' table.")

    # Create Comments table
    c.execute('''CREATE TABLE IF NOT EXISTS Comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    post_id INTEGER NOT NULL,
                    author_id INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (post_id) REFERENCES Posts(id),
                    FOREIGN KEY (author_id) REFERENCES Users(id)
                );''')

    conn.commit()
    print("Database initialized and tables created (if not already present).")
    conn.close()

if __name__ == "__main__":
    initialize_database()
