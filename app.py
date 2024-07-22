from flask import Flask, request, render_template, redirect, url_for, flash, session
import sqlite3
import bcrypt
import os  # New import for file handling

app = Flask(__name__)
app.secret_key = 'yHjLEqrN3b'
UPLOAD_FOLDER = 'static/uploads/'  # New configuration for upload folder
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def get_db_connection():
    conn = sqlite3.connect('user_accounts.db')
    conn.row_factory = sqlite3.Row  # Enables column access by name: row['column_name']
    return conn

def authenticate(username, password):
    conn = get_db_connection()
    user = conn.execute("SELECT password FROM Users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if user:
        password_hash_bin = bytes.fromhex(user['password'])  # Convert hex string back to binary for comparison
        if bcrypt.checkpw(password.encode('utf-8'), password_hash_bin):
            return True
    return False

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['uname']
        password = request.form['psw']
        if authenticate(username, password):
            session['username'] = username
            flash('Login successful!')
            return redirect(url_for('home'))
        else:
            flash('Login failed: Invalid username or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['newuname']
        password = request.form['newpsw']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        hashed_password_hex = hashed_password.hex()  # Convert binary hash to hexadecimal string
        
        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO Users (email, username, password) VALUES (?, ?, ?)", 
                         (email, username, hashed_password_hex))  # Store the hex string
            conn.commit()
            flash('Account created successfully, please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Error: That email or username already exists.')
        finally:
            conn.close()
    return render_template('signup.html')

@app.route('/home')
def home():
    if 'username' not in session:
        flash('You must be logged in to view the home page.')
        return redirect(url_for('login'))
    conn = get_db_connection()
    posts = conn.execute('SELECT p.id, p.content, p.image_url, p.created_at, u.username FROM Posts p JOIN Users u ON p.author_id = u.id ORDER BY p.created_at DESC').fetchall()
    conn.close()
    return render_template('home.html', username=session['username'], posts=posts)

@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'username' not in session:
        flash('You need to be logged in to post.')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        content = request.form['content']
        image = request.files['image']  # New file input handling
        image_url = request.form.get('image_url', '')  # Optional image URL
        
        if not content and not image and not image_url:
            flash('Either post content or an image must be provided.')
            return redirect(url_for('create_post'))
        
        if image and image.filename != '':  # New file saving logic
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
            image.save(image_path)
            image_url = url_for('static', filename=f'uploads/{image.filename}')
        
        try:
            conn = get_db_connection()
            conn.execute('''INSEfRT INTO Posts (author_id, content, image_url) 
                            VALUES ((SELECT id FROM Users WHERE username = ?), ?, ?)''', 
                            (session['username'], content, image_url))
            conn.commit()
        except sqlite3.OperationalError as e:
            flash(f'An error occurred: {e}')
            return redirect(url_for('create_post'))
        finally:
            conn.close()
        
        flash('Your post has been created!')
        return redirect(url_for('home'))
    return render_template('create_post.html')

@app.route('/profile')
def profile():  # New route for profile page
    if 'username' not in session:
        flash('You must be logged in to view the profile page.')
        return redirect(url_for('login'))
    conn = get_db_connection()
    user_id = conn.execute('SELECT id FROM Users WHERE username = ?', (session['username'],)).fetchone()['id']
    posts = conn.execute('SELECT * FROM Posts WHERE author_id = ? ORDER BY created_at DESC', (user_id,)).fetchall()
    conn.close()
    return render_template('profile.html', username=session['username'], posts=posts)

@app.route('/guide')
def guide():
    if 'username' not in session:
        flash('You must be logged in to view the guide.')
        return redirect(url_for('login'))
    return render_template('guide.html', username=session['username'])

@app.route('/DLC')
def DLC():
    if 'username' not in session:
        flash('You must be logged in to view the guide.')
        return redirect(url_for('login'))
    return render_template('guide.html', username=session['username'])


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
