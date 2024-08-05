import sqlite3

def initialize_database():
    try:
        conn = sqlite3.connect('user_accounts.db')
        c = conn.cursor()

        # Create or update Users table
        c.execute('''CREATE TABLE IF NOT EXISTS Users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT NOT NULL UNIQUE,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        profile_image_url TEXT
                    );''')

        # Create or update Posts table
        c.execute('''CREATE TABLE IF NOT EXISTS Posts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        author_id INTEGER NOT NULL,
                        content TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        image_url TEXT,
                        like_count INTEGER DEFAULT 0, -- Default like count is set to 0
                        FOREIGN KEY (author_id) REFERENCES Users(id)
                    );''')
        
        # Create PostLikes table
        c.execute('''CREATE TABLE IF NOT EXISTS PostLikes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        post_id INTEGER NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES Users(id),
                        FOREIGN KEY (post_id) REFERENCES Posts(id),
                        UNIQUE(user_id, post_id) -- Ensure a user can only like a post once
                    );''')
        
        # Create or update Comments table
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
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        conn.close()

# Call the function to initialize the database
initialize_database()
