import sqlite3
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FileField, TextAreaField
from wtforms.validators import InputRequired, Email, Length
import bcrypt
import os
import base64
from io import BytesIO
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect

# updates
app = Flask(__name__)
app.secret_key = 'yHjLEqrN3b'
UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
csrf = CSRFProtect(app)

def get_db_connection():
    conn = sqlite3.connect('user_accounts.db')
    conn.row_factory = sqlite3.Row
    return conn

def authenticate(username, password):
    conn = get_db_connection()
    user = conn.execute("SELECT password FROM Users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if user:
        password_hash_bin = bytes.fromhex(user['password'])
        if bcrypt.checkpw(password.encode('utf-8'), password_hash_bin):
            return True
    return False

class LoginForm(FlaskForm):
    uname = StringField('Username', validators=[InputRequired()])
    psw = PasswordField('Password', validators=[InputRequired()])

class SignupForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    newuname = StringField('Username', validators=[InputRequired()])
    newpsw = PasswordField('Password', validators=[InputRequired(), Length(min=6)])

class CreatePostForm(FlaskForm):
    content = TextAreaField('Content')
    image = FileField('Image')
    image_url = StringField('Image URL')

class UpdateProfileForm(FlaskForm):
    profile_image = FileField('Profile Image')

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.uname.data
        password = form.psw.data
        if authenticate(username, password):
            conn = get_db_connection()
            user = conn.execute('SELECT id FROM Users WHERE username = ?', (username,)).fetchone()
            conn.close()
            
            if user:
                session['username'] = username
                session['user_id'] = user['id']
                flash('Login successful!')
                print('Successfully logged in with user_id:', session['user_id'])  # Tracing
                return redirect(url_for('home'))
            else:
                flash('Login failed: User not found.')
                print('User not found in the database')
        else:
            flash('Login failed: Invalid username or password')
            print('Invalid username or password')
    return render_template('login.html', form=form)




@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        email = form.email.data
        username = form.newuname.data
        password = form.newpsw.data
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        hashed_password_hex = hashed_password.hex()

        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO Users (email, username, password) VALUES (?, ?, ?)", (email, username, hashed_password_hex))
            conn.commit()
            flash('Account created successfully, please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Error: That email or username already exists.')
        finally:
            conn.close()
    return render_template('signup.html', form=form)

@app.route('/home')
def home():
    # Check if user is logged in
    if 'username' not in session:
        flash('You must be logged in to view the home page.')
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    if user_id is None:
        flash('User ID is not available in session.')
        return redirect(url_for('logout'))

    # Check for an error flag in the session
    if 'error_redirected' in session and session['error_redirected']:
        flash('An error occurred previously. Please try again.')
        session.pop('error_redirected')  # Clear the error flag
        return render_template('home.html', username=session['username'], posts=[])

    conn = get_db_connection()
    try:
        # Print query for debugging
        print("Executing SQL query to fetch posts")

        posts = conn.execute(
            '''SELECT p.id, p.content, p.image_url, p.created_at, u.username,
                      COALESCE(l.like_count, 0) AS like_count,
                      COALESCE(COUNT(CASE WHEN l2.user_id = ? THEN 1 END), 0) AS is_liked_by_current_user
               FROM Posts p
               JOIN Users u ON p.author_id = u.id
               LEFT JOIN (SELECT post_id, COUNT(*) AS like_count FROM Likes GROUP BY post_id) l ON p.id = l.post_id
               LEFT JOIN Likes l2 ON p.id = l2.post_id
               GROUP BY p.id, p.content, p.image_url, p.created_at, u.username, l.like_count
               ORDER BY p.created_at DESC''',
            (user_id,)
        ).fetchall()

        # Print fetched posts for debugging
        print("Fetched posts:", posts)

    except sqlite3.OperationalError as e:
        flash(f'An error occurred while querying posts: {e}')
        conn.close()
        session['error_redirected'] = True  # Set the error flag
        return redirect(url_for('home'))  # Redirect to home to avoid loop
    finally:
        conn.close()

    # Reset error flag if successful
    session.pop('error_redirected', None)

    # Debugging information
    print('Session:', session)
    print('Posts:', posts)

    return render_template('home.html', username=session['username'], posts=posts)







@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'user_id' not in session:
        flash('You need to be logged in to post.')
        return redirect(url_for('login'))

    form = CreatePostForm()
    if form.validate_on_submit():
        content = form.content.data
        image = form.image.data
        image_url = form.image_url.data

        if not content and not image and not image_url:
            flash('Either post content or an image must be provided.')
            return redirect(url_for('create_post'))

        # Process the image if provided
        if image and image.filename != '':
            # Convert image to Base64
            image_stream = BytesIO(image.read())
            image_base64 = base64.b64encode(image_stream.getvalue()).decode('utf-8')
            image_url = f"data:image/jpeg;base64,{image_base64}"

        try:
            conn = get_db_connection()
            conn.execute('''INSERT INTO Posts (author_id, content, image_url) 
                            VALUES (?, ?, ?)''', (session['user_id'], content, image_url))
            conn.commit()
            flash('Your post has been created!')
            return redirect(url_for('home'))
        except sqlite3.OperationalError as e:
            flash(f'An error occurred: {e}')
            return redirect(url_for('create_post'))
        finally:
            conn.close()

    return render_template('create_post.html', form=form)

@app.route('/profile')
def profile():
    if 'username' not in session:
        flash('You must be logged in to view the profile page.')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user_id = conn.execute('SELECT id FROM Users WHERE username = ?', (session['username'],)).fetchone()['id']
    posts = conn.execute('SELECT * FROM Posts WHERE author_id = ? ORDER BY created_at DESC', (user_id,)).fetchall()
    user = conn.execute('SELECT username, email FROM Users WHERE username = ?', (session['username'],)).fetchone()
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
    if 'username' not in session:
        flash('You must be logged in to perform this action.')
        return redirect(url_for('login'))

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

    form = UpdateProfileForm()
    if form.validate_on_submit():
        file = form.profile_image.data
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            conn = get_db_connection()
            conn.execute('UPDATE Users SET profile_image_url = ? WHERE username = ?', (url_for('static', filename=f'uploads/{filename}'), session['username']))
            conn.commit()
            conn.close()

            flash('Profile image updated successfully.')
            return redirect(url_for('profile'))

        flash('Invalid file format')
        return redirect(url_for('profile'))

    flash('No file part')
    return redirect(url_for('profile'))

def allowed_file(filename):
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)  # Ensure user_id is also removed
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/get_like_count')
def get_like_count():
    post_id = request.args.get('post_id', type=int)
    conn = get_db_connection()
    like_count = conn.execute('SELECT COUNT(*) FROM Likes WHERE post_id = ?', (post_id,)).fetchone()[0]
    conn.close()
    return jsonify({'like_count': like_count})

@app.route('/like_post', methods=['POST'])
def like_post():
    if 'user_id' not in session:
        return jsonify({'error': 'User not logged in'}), 403

    post_id = request.form.get('post_id')
    user_id = session['user_id']
    conn = get_db_connection()

    try:
        existing_like = conn.execute('SELECT * FROM Likes WHERE post_id = ? AND user_id = ?', (post_id, user_id)).fetchone()
        if existing_like:
            conn.execute('DELETE FROM Likes WHERE post_id = ? AND user_id = ?', (post_id, user_id))
        else:
            conn.execute('INSERT INTO Likes (post_id, user_id) VALUES (?, ?)', (post_id, user_id))
        conn.commit()
        like_count = conn.execute('SELECT COUNT(*) FROM Likes WHERE post_id = ?', (post_id,)).fetchone()[0]
        return jsonify({'like_count': like_count})
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)
