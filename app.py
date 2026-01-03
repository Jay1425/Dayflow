from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import json
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from pip._vendor import cachecontrol
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fdbdfnhbidfhibfhijmhikwsgoihgepwsofbfgbjfghnirfhsjr')

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com')
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = os.getenv('OAUTHLIB_INSECURE_TRANSPORT', '1')  # For development only

# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "app.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    newsletter = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if provided password matches hash"""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

@app.route('/google-login', methods=['POST'])
def google_login():
    """Handle Google OAuth login"""
    try:
        token = request.form.get('credential')
        
        # Verify the token
        idinfo = id_token.verify_oauth2_token(
            token, 
            google_requests.Request(), 
            GOOGLE_CLIENT_ID
        )
        
        # Get user info from Google
        google_id = idinfo['sub']
        email = idinfo['email']
        name = idinfo.get('name', '')
        
        # Check if user exists
        user = User.query.filter_by(email=email).first()
        
        if not user:
            # Create new user with Google info
            username = email.split('@')[0] + '_google_' + google_id[:6]
            user = User(
                fullname=name,
                username=username,
                email=email,
                newsletter=False
            )
            # Set a random password (won't be used for Google login)
            user.set_password(os.urandom(24).hex())
            db.session.add(user)
            db.session.commit()
            flash('Account created successfully with Google!', 'success')
        else:
            flash('Login successful!', 'success')
        
        # Log the user in
        session['user_id'] = user.id
        session['user'] = user.username
        return redirect(url_for('dashboard'))
        
    except ValueError as e:
        flash(f'Invalid Google token: {str(e)}', 'error')
        return redirect(url_for('login'))
    except Exception as e:
        flash(f'An error occurred during Google login: {str(e)}', 'error')
        return redirect(url_for('login'))

# Create database tables
with app.app_context():
    db.create_all()
    
    # Create demo user if it doesn't exist
    demo_user = User.query.filter_by(username='demo').first()
    if not demo_user:
        demo_user = User(
            fullname='Demo User',
            username='demo',
            email='demo@example.com',
            newsletter=True
        )
        demo_user.set_password('password')
        db.session.add(demo_user)
        db.session.commit()

@app.route('/')
def home():
    """Home page route"""
    return render_template('index.html')

@app.route('/about')
def about():
    """About page route"""
    return render_template('about.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page route"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Find user in database
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['user'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Try demo/password', 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Signup page route"""
    if request.method == 'POST':
        fullname = request.form.get('fullname', '')
        username = request.form.get('username', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm-password', '')
        terms = request.form.get('terms')
        newsletter = request.form.get('newsletter') == 'on'
        
        # Basic validation
        if not all([fullname, username, email, password]):
            flash('Please fill in all required fields.', 'error')
        elif password != confirm_password:
            flash('Passwords do not match.', 'error')
        elif not terms:
            flash('Please agree to the Terms of Service.', 'error')
        elif User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another.', 'error')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered. Please use another.', 'error')
        elif len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
        else:
            # Create new user
            user = User(
                fullname=fullname,
                username=username,
                email=email,
                newsletter=newsletter
            )
            user.set_password(password)
            
            try:
                db.session.add(user)
                db.session.commit()
                flash('Account created successfully! Please login.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash('An error occurred while creating your account. Please try again.', 'error')
    
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    """Dashboard page route (requires login)"""
    if 'user_id' not in session:
        flash('Please login to access the dashboard.', 'error')
        return redirect(url_for('login'))
    
    # Get user data from database
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('User not found. Please login again.', 'error')
        return redirect(url_for('login'))
    
    # Get user stats
    total_users = User.query.count()
    user_data = {
        'fullname': user.fullname,
        'username': user.username,
        'email': user.email,
        'joined': user.created_at.strftime('%B %Y'),
        'newsletter': user.newsletter,
        'total_users': total_users
    }
    
    return render_template('dashboard.html', user=session['user'], user_data=user_data)

@app.route('/logout')
def logout():
    """Logout route"""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/profile')
def profile():
    """User profile page"""
    if 'user_id' not in session:
        flash('Please login to access your profile.', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('User not found. Please login again.', 'error')
        return redirect(url_for('login'))
    
    return render_template('profile.html', user=user)

@app.errorhandler(404)
def page_not_found(e):
    """404 error handler"""
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)