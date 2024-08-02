from flask import Flask, request, render_template, redirect, url_for, flash, session
import sqlite3
import bcrypt
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'yHjLEqrN3b'
UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def get_db_connection():
    conn = sqlite3.connect('user_accounts.db')
    conn.row_factory = sqlite3.Row
    return conn

def authenticate(username, password):
    conn = get_db_connection()
    user = conn.execute(
        "SELECT password FROM Users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if user:
        password_hash_bin = bytes.fromhex(user['password'])
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
        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'), bcrypt.gensalt())
        hashed_password_hex = hashed_password.hex()

        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO Users (email, username, password) VALUES (?, ?, ?)",
                         (email, username, hashed_password_hex))
            conn.commit()
            flash('Account created successfully, please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Error: That email or username already exists.')
        finally:
            conn.close()
    return render_template('signup.html')

@app.route('/vote/<int:post_id>/<string:vote_type>', methods=['POST'])
def vote(post_id, vote_type):
    if 'username' not in session:
        flash('You must be logged in to vote.')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user_id = conn.execute('SELECT id FROM Users WHERE username = ?',
                           (session['username'],)).fetchone()['id']

    if vote_type == 'up':
        conn.execute('INSERT INTO Votes (post_id, user_id, vote_type) VALUES (?, ?, ?)',
                     (post_id, user_id, 'up'))
    elif vote_type == 'down':
        conn.execute('INSERT INTO Votes (post_id, user_id, vote_type) VALUES (?, ?, ?)',
                     (post_id, user_id, 'down'))

    conn.commit()

    # Update post's vote count
    vote_count = conn.execute('''SELECT COUNT(*) FROM Votes WHERE post_id = ? AND vote_type = ?''',
                              (post_id, vote_type)).fetchone()[0]

    conn.execute('UPDATE Posts SET vote_count = ? WHERE id = ?',
                 (vote_count, post_id))
    conn.commit()
    conn.close()

    return redirect(url_for('home'))

@app.route('/home')
def home():
    if 'username' not in session:
        flash('You must be logged in to view the home page.')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    posts = conn.execute(
        'SELECT p.id, p.content, p.image_url, p.created_at, u.username, '
        'COALESCE(SUM(CASE WHEN c.id IS NOT NULL THEN 1 ELSE 0 END), 0) AS comment_count '
        'FROM Posts p '
        'JOIN Users u ON p.author_id = u.id '
        'LEFT JOIN Comments c ON p.id = c.post_id '
        'GROUP BY p.id, p.content, p.image_url, p.created_at, u.username '
        'ORDER BY p.created_at DESC'
    ).fetchall()
    conn.close()
    return render_template('home.html', username=session['username'], posts=posts)

@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'username' not in session:
        flash('You need to be logged in to post.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        content = request.form['content']
        image = request.files['image']
        image_url = request.form.get('image_url', '')

        if not content and not image and not image_url:
            flash('Either post content or an image must be provided.')
            return redirect(url_for('create_post'))

        if image and image.filename != '':
            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(image_path)
            image_url = url_for('static', filename=f'uploads/{filename}')

        try:
            conn = get_db_connection()
            conn.execute('''INSERT INTO Posts (author_id, content, image_url) 
                            VALUES ((SELECT id FROM Users WHERE username = ?), ?, ?)''',
                         (session['username'], content, image_url))
            conn.commit()
            flash('Your post has been created!')
            return redirect(url_for('home'))
        except sqlite3.OperationalError as e:
            flash(f'An error occurred: {e}')
            return redirect(url_for('create_post'))
        finally:
            conn.close()

    return render_template('create_post.html')

@app.route('/profile')
def profile():
    if 'username' not in session:
        flash('You must be logged in to view the profile page.')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user_id = conn.execute('SELECT id FROM Users WHERE username = ?',
                           (session['username'],)).fetchone()['id']
    posts = conn.execute(
        'SELECT * FROM Posts WHERE author_id = ? ORDER BY created_at DESC', (user_id,)).fetchall()
    user = conn.execute(
        'SELECT username, email FROM Users WHERE username = ?', (session['username'],)).fetchone()
    conn.close()

    return render_template('profile.html', username=session['username'], posts=posts, user=user)

@app.route('/guide')
def guide():
    if 'username' not in session:
        flash('You must be logged in to view the guide.')
        return redirect(url_for('login'))
    return render_template('guide.html', username=session['username'])

@app.route('/DLC')
def DLC():
    if 'username' not in session:
        flash('You must be logged in to view the DLC page.')
        return redirect(url_for('login'))

    page = request.args.get('page', 1, type=int)
    content = f'Blah{page}'
    return render_template('DLC.html', content=content)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM Posts WHERE id = ?', (post_id,))
    conn.commit()
    conn.close()
    flash('Post deleted successfully', 'success')
    return redirect(url_for('profile'))

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'username' not in session:
        flash('You must be logged in to update your profile.')
        return redirect(url_for('login'))

    if 'profile_image' not in request.files:
        flash('No file part')
        return redirect(url_for('profile'))

    file = request.files['profile_image']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('profile'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        flash('Profile image updated successfully.')
        return redirect(url_for('profile'))

    flash('Invalid file format')
    return redirect(url_for('profile'))

def allowed_file(filename):
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
