from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, make_response, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from sqlalchemy.exc import IntegrityError
import secrets
from io import BytesIO

# Books are stored in a folder named "books" within the same directory as your Flask app
BOOKS_FOLDER = os.path.join(os.getcwd(), 'books')

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    reset_code = db.Column(db.String(10), unique=True)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(200), nullable=False)

def create_default_admin():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        hashed_password = generate_password_hash('admin', method='pbkdf2:sha256')
        admin = User(username='admin', password=hashed_password, role='admin')
        db.session.add(admin)
        db.session.commit()

# Check if the database file exists, if not, create it
if not os.path.exists('instance/library.db'):
    with app.app_context():
        db.create_all()
    # Call this function to create the default admin
        create_default_admin()
        
@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

# Function to generate a 10-digit numerical code
def generate_reset_code():
    return ''.join(secrets.choice('0123456789') for _ in range(10))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Generate verification code
        verification_code = generate_reset_code()

        # Store user data in the database
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role='user', reset_code=verification_code)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully. Your verification code is: {}'.format(verification_code), 'success')

            # # Generate a text file with the verification code
            # response = make_response(verification_code)
            # response.headers["Content-Disposition"] = "attachment; filename=reset_code.txt"
           
            file_content = verification_code.encode('utf-8')
            response = send_file(BytesIO(file_content),
                                 mimetype='text/plain',
                                 as_attachment=True,
                                 download_name='reset_code.txt')
            response.headers['X-Redirect'] = url_for('login')
            return response
            
        
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred while registering. Please try again.', 'danger')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            flash('Login Failed. Check your username and/or password', 'danger')
    return render_template('login.html')

@app.route('/reset', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        reset_code = request.form['reset_code']
        new_password = request.form['new_password']
        
        user = User.query.filter_by(username=username, reset_code=reset_code).first()
        if user:
            user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
            db.session.commit()
            flash('Password reset successfully. You can now login with your new password.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid username or reset code. Please try again.', 'danger')
            return redirect(url_for('reset_password'))
    return render_template('reset.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Default behavior: Display all books
    books = Book.query.all()
    query = ''

    # If the request method is POST, it means a search query was submitted
    if request.method == 'POST':
        query = request.form['query']
        books = Book.query.filter(Book.title.contains(query)).all()

    return render_template('dashboard.html', username=session['username'], books=books, query=query)

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    books = Book.query.all()
    return render_template('admin.html', books=books)

@app.route('/add_book', methods=['GET', 'POST'])
def add_book():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        file_path = request.form['file_path']
        new_book = Book(title=title, author=author, file_path=file_path)
        db.session.add(new_book)
        db.session.commit()
        flash('Book added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('add_book.html')

@app.route('/search_results', methods=['GET', 'POST'])
def search_results():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    query = request.form['query']
    books = Book.query.filter(Book.title.contains(query)).all()
    return render_template('dashboard.html', books=books)
    

@app.route('/download_book/<int:book_id>', methods=['GET'])
def download_book(book_id):
    # Fetch the book details from the database using book_id
    book = Book.query.get(book_id)
    print(book.title)
    if book:
        # Implement code to send the book file for download
        # For example, you can use send_from_directory
        return send_from_directory(directory=BOOKS_FOLDER, path=book.file_path, as_attachment=True)
    else:
        flash('Book not found!', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/logout', methods=['POST'])
def logout():
    # Clear session data
    session.pop('user_id', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/manage_roles', methods=['GET', 'POST'])
def manage_roles():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    users = User.query.all()

    if request.method == 'POST':
        user_id = request.form['user_id']
        new_role = request.form['new_role']
        user = User.query.get(user_id)
        if user:
            user.role = new_role
            db.session.commit()
            flash('Role updated successfully.', 'success')
        else:
            flash('User not found.', 'danger')
        return redirect(url_for('manage_roles'))

    return render_template('manage_roles.html', users=users)

if __name__ == '__main__':
    app.run(debug=True)
