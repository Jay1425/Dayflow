from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta
from functools import wraps
import os
import json
import secrets
import string
import random
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from pip._vendor import cachecontrol
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fdbdfnhbidfhibfhijmhikwsgoihgepwsofbfgbjfghnirfhsjr')

# Company Configuration
COMPANY_CODE = os.getenv('COMPANY_CODE', 'DF')  # Dayflow company code

# Email Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@dayflow.com')

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com')
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = os.getenv('OAUTHLIB_INSECURE_TRANSPORT', '1')  # For development only

# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "app.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)


# ============= HELPER FUNCTIONS =============

def generate_login_id(fullname, year_of_joining, company_name=None):
    """
    Generate login ID: DFJARA20260001 or ODJARA20260001
    Format: [CompanyCode(2 letters)][First2LettersFirstName][First2LettersLastName][Year][Serial]
    Example: DFJARA20260001 (DF + JA + RA + 2026 + 0001) for Dayflow company, Jay Raychura
    Example: ODJARA20260001 (OD + JA + RA + 2026 + 0001) for Odoo company, Jay Raychura
    
    Args:
        fullname: Full name of the user
        year_of_joining: Year the user joined
        company_name: Company name (optional). If not provided, uses COMPANY_CODE from env
    """
    names = fullname.strip().split()
    
    # Get company code (first 2 letters of company name)
    if company_name:
        company_code = company_name.strip()[:2].upper()
    else:
        company_code = COMPANY_CODE
    
    # Get first 2 letters of first name (or pad with X if too short)
    first_letters = (names[0][:2].upper() if len(names) > 0 and len(names[0]) >= 2 
                     else (names[0][0].upper() + 'X' if len(names) > 0 and len(names[0]) == 1 
                           else 'XX'))
    
    # Get first 2 letters of last name (or pad with X if too short)
    last_letters = (names[-1][:2].upper() if len(names) > 1 and len(names[-1]) >= 2 
                    else (names[-1][0].upper() + 'X' if len(names) > 1 and len(names[-1]) == 1 
                          else 'XX'))
    
    # Get count of users created in this year
    count = User.query.filter_by(year_of_joining=year_of_joining).count()
    serial = str(count + 1).zfill(4)
    
    login_id = f"{company_code}{first_letters}{last_letters}{year_of_joining}{serial}"
    return login_id


def generate_temp_password(length=12):
    """Generate a secure temporary password"""
    alphabet = string.ascii_letters + string.digits + '!@#$%^&*'
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password


def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])


def send_otp_email(email, fullname, login_id, otp):
    """Send OTP verification email to new user"""
    try:
        print(f"📧 Attempting to send email to: {email}")
        print(f"📧 MAIL_USERNAME: {app.config.get('MAIL_USERNAME')}")
        print(f"📧 MAIL_SERVER: {app.config.get('MAIL_SERVER')}:{app.config.get('MAIL_PORT')}")
        
        msg = Message(
            subject='Dayflow HRMS - Email Verification',
            recipients=[email]
        )
        
        msg.html = f'''
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0; text-align: center;">
                <h1 style="color: white; margin: 0;">🚀 Welcome to Dayflow HRMS</h1>
            </div>
            
            <div style="background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px;">
                <p style="font-size: 16px; color: #333;">Hi <strong>{fullname}</strong>,</p>
                
                <p style="color: #666;">Your Dayflow HRMS account has been created successfully!</p>
                
                <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #667eea;">
                    <p style="margin: 0; color: #666;"><strong>Your Login ID:</strong></p>
                    <p style="font-size: 24px; font-weight: bold; color: #333; margin: 10px 0;">{login_id}</p>
                </div>
                
                <div style="background: #fff3cd; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ffc107;">
                    <p style="margin: 0; color: #856404;"><strong>🔐 Your Verification Code:</strong></p>
                    <p style="font-size: 32px; font-weight: bold; color: #856404; margin: 10px 0; letter-spacing: 5px;">{otp}</p>
                    <p style="color: #856404; margin: 10px 0; font-size: 14px;">⏱️ This code expires in 10 minutes</p>
                </div>
                
                <div style="background: #e3f2fd; padding: 15px; border-radius: 8px; margin: 20px 0;">
                    <h3 style="color: #1976d2; margin-top: 0;">📝 Next Steps:</h3>
                    <ol style="color: #666; line-height: 1.8;">
                        <li>Go to the Dayflow login page</li>
                        <li>Enter your <strong>Login ID</strong> and <strong>temporary password</strong> (provided separately)</li>
                        <li>Verify your email using the OTP above</li>
                        <li>Set your secure password</li>
                        <li>Start using Dayflow!</li>
                    </ol>
                </div>
                
                <p style="color: #999; font-size: 12px; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
                    <strong>Security Note:</strong> Never share your OTP with anyone. Dayflow staff will never ask for your OTP or password.
                </p>
            </div>
        </body>
        </html>
        '''
        
        mail.send(msg)
        print(f"✅ Email sent successfully to {email}")
        return True
    except Exception as e:
        print(f"❌ Email sending failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def validate_password_strength(password):
    """Validate password meets security requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        return False, "Password must contain at least one special character"
    return True, "Password is strong"


def role_required(*allowed_roles):
    """Decorator to protect routes based on role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please login to access this page.', 'error')
                return redirect(url_for('login'))
            
            user = User.query.get(session['user_id'])
            if not user or user.role not in allowed_roles:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('unauthorized'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def validate_password(password):
    """
    Validate password security requirements:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    import re
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit."
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)."
    
    return True, "Password is strong."


# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)  # Keep for legacy, but use login_id
    login_id = db.Column(db.String(20), unique=True, nullable=True)  # OIJARA20260001 format
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='Employee')  # Admin, HR Officer, Employee
    company = db.Column(db.String(100), nullable=True)  # Company name (e.g., Dayflow, Odoo)
    year_of_joining = db.Column(db.Integer, nullable=True)
    is_first_login = db.Column(db.Boolean, default=True)
    email_verified = db.Column(db.Boolean, default=False)  # Email OTP verification status
    otp = db.Column(db.String(6), nullable=True)  # Current OTP
    otp_expiry = db.Column(db.DateTime, nullable=True)  # OTP expiration time
    otp_attempts = db.Column(db.Integer, default=0)  # Track failed OTP attempts
    last_otp_request = db.Column(db.DateTime, nullable=True)  # Rate limiting
    newsletter = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Profile management fields
    profile_photo = db.Column(db.String(200), nullable=True)
    resume_file = db.Column(db.String(200), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    department = db.Column(db.String(100), nullable=True)
    designation = db.Column(db.String(100), nullable=True)
    date_of_joining = db.Column(db.Date, nullable=True)
    reporting_manager = db.Column(db.String(100), nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_login_device = db.Column(db.String(200), nullable=True)
    password_updated_at = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if provided password matches hash"""
        return check_password_hash(self.password_hash, password)
    
    def set_otp(self, otp):
        """Set OTP with 10-minute expiration"""
        self.otp = otp
        self.otp_expiry = datetime.now() + timedelta(minutes=10)
        self.otp_attempts = 0
        self.last_otp_request = datetime.now()
    
    def verify_otp(self, otp):
        """Verify OTP is correct and not expired"""
        if not self.otp or not self.otp_expiry:
            return False
        if datetime.now() > self.otp_expiry:
            return False
        if self.otp != otp:
            self.otp_attempts += 1
            return False
        return True
    
    def clear_otp(self):
        """Clear OTP after successful verification"""
        self.otp = None
        self.otp_expiry = None
        self.otp_attempts = 0
    
    def __repr__(self):
        return f'<User {self.username}>'


class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    check_in = db.Column(db.DateTime)
    check_out = db.Column(db.DateTime)
    status = db.Column(db.String(50), default='Absent')
    duration_minutes = db.Column(db.Integer, default=0)

    __table_args__ = (db.UniqueConstraint('user_id', 'date', name='uq_user_date'),)

    def compute_status(self):
        if self.check_in and self.check_out:
            total_minutes = int((self.check_out - self.check_in).total_seconds() // 60)
            self.duration_minutes = total_minutes
            if total_minutes >= 8 * 60:
                self.status = 'Present'
            elif total_minutes >= 4 * 60:
                self.status = 'Half Day'
            else:
                self.status = 'Short Shift'
        elif self.check_in and not self.check_out:
            self.status = 'In Progress'
        else:
            self.status = 'Absent'
        return self.status

    def to_dict(self):
        return {
            'date': self.date.isoformat(),
            'check_in': self.check_in.isoformat() if self.check_in else None,
            'check_out': self.check_out.isoformat() if self.check_out else None,
            'status': self.status,
            'duration_minutes': self.duration_minutes
        }


class Leave(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    leave_type = db.Column(db.String(50), nullable=False)  # Paid Leave, Sick Leave, Unpaid Leave
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    total_days = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Pending')  # Pending, Approved, Rejected
    admin_comment = db.Column(db.Text)  # For future admin approval
    applied_on = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('leaves', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'leave_type': self.leave_type,
            'start_date': self.start_date.isoformat(),
            'end_date': self.end_date.isoformat(),
            'total_days': self.total_days,
            'reason': self.reason,
            'status': self.status,
            'admin_comment': self.admin_comment,
            'applied_on': self.applied_on.strftime('%b %d, %Y')
        }


class Salary(db.Model):
    """Salary information for employees"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    
    # Wage details (stored as JSON)
    monthly_wage = db.Column(db.Float, nullable=False, default=0.0)
    yearly_wage = db.Column(db.Float, nullable=False, default=0.0)
    working_days_per_week = db.Column(db.Integer, default=5)
    daily_working_hours = db.Column(db.Float, default=8.0)
    break_time_hours = db.Column(db.Float, default=1.0)
    
    # Salary breakdown
    basic_salary = db.Column(db.Float, default=0.0)
    hra = db.Column(db.Float, default=0.0)
    standard_allowance = db.Column(db.Float, default=1500.0)
    performance_bonus = db.Column(db.Float, default=0.0)
    lta = db.Column(db.Float, default=0.0)
    fixed_allowance = db.Column(db.Float, default=0.0)
    gross_salary = db.Column(db.Float, default=0.0)
    
    # PF details
    employee_pf_percent = db.Column(db.Float, default=12.0)
    employer_pf_percent = db.Column(db.Float, default=12.0)
    employee_pf_amount = db.Column(db.Float, default=0.0)
    employer_pf_amount = db.Column(db.Float, default=0.0)
    
    # Tax deductions
    professional_tax = db.Column(db.Float, default=200.0)
    
    # Net salary
    net_salary = db.Column(db.Float, default=0.0)
    
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def calculate_breakdown(self):
        """Calculate salary breakdown based on monthly wage"""
        self.yearly_wage = self.monthly_wage * 12
        self.basic_salary = self.monthly_wage * 0.5
        self.hra = self.basic_salary * 0.5
        self.performance_bonus = self.basic_salary * 0.0833
        self.lta = self.basic_salary * 0.08333
        
        # Calculate fixed allowance to match monthly wage
        total_components = (self.basic_salary + self.hra + self.standard_allowance + 
                          self.performance_bonus + self.lta)
        self.fixed_allowance = max(0, self.monthly_wage - total_components)
        
        self.gross_salary = self.monthly_wage
        
        # Calculate PF amounts
        self.employee_pf_amount = self.basic_salary * (self.employee_pf_percent / 100)
        self.employer_pf_amount = self.basic_salary * (self.employer_pf_percent / 100)
        
        # Calculate net salary
        total_deductions = self.employee_pf_amount + self.professional_tax
        self.net_salary = self.gross_salary - total_deductions
    
    def to_dict(self):
        return {
            'wage_details': {
                'monthly_wage': self.monthly_wage,
                'yearly_wage': self.yearly_wage,
                'working_days_per_week': self.working_days_per_week,
                'daily_working_hours': self.daily_working_hours,
                'break_time_hours': self.break_time_hours
            },
            'breakdown': {
                'basic': self.basic_salary,
                'hra': self.hra,
                'standard_allowance': self.standard_allowance,
                'performance_bonus': self.performance_bonus,
                'lta': self.lta,
                'fixed_allowance': self.fixed_allowance,
                'gross_salary': self.gross_salary
            },
            'pf': {
                'employee_percent': self.employee_pf_percent,
                'employer_percent': self.employer_pf_percent,
                'employee_amount': self.employee_pf_amount,
                'employer_amount': self.employer_pf_amount
            },
            'tax': {
                'professional_tax': self.professional_tax
            },
            'net_salary': self.net_salary
        }


def get_today_attendance(user_id: int):
    today = date.today()
    record = Attendance.query.filter_by(user_id=user_id, date=today).first()
    return record


def build_weekly_overview(user_id: int, days: int = 7):
    today = date.today()
    start = today - timedelta(days=days - 1)
    records = Attendance.query.filter(
        Attendance.user_id == user_id,
        Attendance.date >= start,
        Attendance.date <= today
    ).all()

    record_map = {(rec.date): rec for rec in records}
    overview = []

    for i in range(days):
        day = start + timedelta(days=i)
        rec = record_map.get(day)
        if rec:
            status = rec.compute_status()
            ci = rec.check_in.strftime('%I:%M %p') if rec.check_in else '—'
            co = rec.check_out.strftime('%I:%M %p') if rec.check_out else '—'
            duration = f"{rec.duration_minutes // 60}h {rec.duration_minutes % 60}m" if rec.duration_minutes else '—'
        else:
            status = 'Absent'
            ci = '—'
            co = '—'
            duration = '—'

        overview.append({
            'date': day.strftime('%a, %b %d'),
            'status': status,
            'check_in': ci,
            'check_out': co,
            'duration': duration
        })

    return overview


def build_action_state(record: Attendance | None):
    if record is None:
        return {'can_check_in': True, 'can_check_out': False}
    if record.check_in and not record.check_out:
        return {'can_check_in': False, 'can_check_out': True}
    return {'can_check_in': False, 'can_check_out': False}


def mark_absent_for_date(target_date: date):
    """
    Mark all users as absent for the given date if they haven't checked in.
    This function creates Attendance records with status='Absent' for users
    who have no attendance record for the specified date.
    
    Returns: dict with 'marked_absent' count and 'already_present' count
    """
    all_users = User.query.all()
    marked_count = 0
    already_present_count = 0
    
    for user in all_users:
        existing_record = Attendance.query.filter_by(
            user_id=user.id,
            date=target_date
        ).first()
        
        if not existing_record:
            # Create absent record
            absent_record = Attendance(
                user_id=user.id,
                date=target_date,
                status='Absent',
                check_in=None,
                check_out=None,
                duration_minutes=0
            )
            db.session.add(absent_record)
            marked_count += 1
        else:
            already_present_count += 1
    
    db.session.commit()
    return {
        'marked_absent': marked_count,
        'already_present': already_present_count,
        'date': target_date.isoformat()
    }

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
    
    # Create default admin if doesn't exist
    admin_user = User.query.filter_by(role='Admin').first()
    if not admin_user:
        admin_user = User(
            fullname='System Administrator',
            username='admin',
            login_id='OISA20260001',  # System Admin 2026 0001
            email='jayraychura22@gmail.com',
            role='Admin',
            year_of_joining=2026,
            is_first_login=False,  # Admin doesn't need password change
            newsletter=False
        )
        admin_user.set_password('admin123')  # Change this in production!
        db.session.add(admin_user)
        db.session.commit()
        print("✅ Default admin created: login_id=OISA20260001, password=admin123")
    
    # Create demo employee if doesn't exist
    demo_user = User.query.filter_by(username='demo').first()
    if not demo_user:
        demo_user = User(
            fullname='Demo Employee',
            username='demo',
            login_id='OIDE20260002',  # Demo Employee 2026 0002
            email='demo@dayflow.com',
            role='Employee',
            year_of_joining=2026,
            is_first_login=False,
            newsletter=True
        )
        demo_user.set_password('password')
        db.session.add(demo_user)
        db.session.commit()
        print("✅ Demo employee created: login_id=OIDE20260002, password=password")

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
    """Login page route - supports login_id or email"""
    if request.method == 'POST':
        identifier = request.form.get('username', '').strip()  # Can be login_id or email
        password = request.form.get('password', '')
        
        # Try to find user by login_id first, then email, then username
        user = User.query.filter(
            db.or_(
                User.login_id == identifier,
                User.email == identifier,
                User.username == identifier
            )
        ).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['user'] = user.username
            session['role'] = user.role
            session['is_first_login'] = user.is_first_login
            
            # Check if first login - requires password setup
            if user.is_first_login:
                flash('Welcome! Please change your password for security.', 'warning')
                return redirect(url_for('change_password'))
            
            flash('Login successful!', 'success')
            
            # Redirect to attendance page for employees to check-in
            if user.role == 'Employee':
                return redirect(url_for('attendance'))
            # Admin/HR go to their respective dashboards
            elif user.role == 'Admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'HR Officer':
                return redirect(url_for('hr_dashboard'))
            else:
                return redirect(url_for('employees'))
        else:
            flash('Invalid credentials. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
@role_required('Admin', 'HR Officer')
def signup():
    """Signup page route - RESTRICTED to Admin/HR only"""
    if request.method == 'POST':
        fullname = request.form.get('fullname', '').strip()
        email = request.form.get('email', '').strip()
        company = request.form.get('company', '').strip()
        role = request.form.get('role', 'Employee')
        year_of_joining = int(request.form.get('year_of_joining', datetime.now().year))
        
        # Get current user for permission check
        current_user = User.query.get(session['user_id'])
        
        # Validation: HR Officers can only create Employees
        if current_user.role == 'HR Officer' and role != 'Employee':
            flash('HR Officers can only create Employee accounts.', 'error')
            return redirect(url_for('signup'))
        
        # Admin can create HR Officers and Employees (but not other Admins for security)
        if role not in ['Employee', 'HR Officer']:
            flash('Invalid role selected.', 'error')
            return redirect(url_for('signup'))
        
        # Basic validation
        if not all([fullname, email, company]):
            flash('Please fill in all required fields.', 'error')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered. Please use another.', 'error')
        else:
            # Generate login credentials
            login_id = generate_login_id(fullname, year_of_joining, company)
            temp_password = generate_temp_password()
            username = login_id  # Use login_id as username
            
            # Validate password security
            is_valid, error_msg = validate_password(temp_password)
            if not is_valid:
                # Regenerate until we get a secure password
                while not is_valid:
                    temp_password = generate_temp_password()
                    is_valid, error_msg = validate_password(temp_password)
            
            # Generate OTP for email verification
            otp = generate_otp()
            
            # Create new user
            user = User(
                fullname=fullname,
                username=username,
                login_id=login_id,
                email=email,
                company=company,
                role=role,
                year_of_joining=year_of_joining,
                is_first_login=True,
                email_verified=True  # OTP verification disabled
            )
            user.set_password(temp_password)
            
            try:
                db.session.add(user)
                db.session.commit()
                
                # Store credentials in session to display
                session['new_user_login_id'] = login_id
                session['new_user_temp_password'] = temp_password
                session['new_user_fullname'] = fullname
                session['new_user_email'] = email
                
                flash(f'{role} account created successfully!', 'success')
                return redirect(url_for('user_created'))
                    
            except Exception as e:
                db.session.rollback()
                flash('An error occurred while creating the account. Please try again.', 'error')
    
    return render_template('signup.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard page route (requires login) - Employee Dashboard"""
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
        'login_id': user.login_id or user.username,
        'email': user.email,
        'role': user.role,
        'joined': user.created_at.strftime('%B %Y'),
        'newsletter': user.newsletter,
        'total_users': total_users
    }
    
    return render_template('dashboard.html', user=session['user'], user_data=user_data)


@app.route('/admin/dashboard')
@role_required('Admin')
def admin_dashboard():
    """Admin Dashboard - Full system access"""
    user = User.query.get(session['user_id'])
    
    # Admin stats
    total_employees = User.query.filter_by(role='Employee').count()
    total_hr = User.query.filter_by(role='HR Officer').count()
    total_attendance_today = Attendance.query.filter_by(date=date.today()).count()
    pending_leaves = Leave.query.filter_by(status='Pending').count()
    
    admin_data = {
        'fullname': user.fullname,
        'login_id': user.login_id,
        'total_employees': total_employees,
        'total_hr': total_hr,
        'total_attendance_today': total_attendance_today,
        'pending_leaves': pending_leaves
    }
    
    return render_template('admin_dashboard.html', user=session['user'], admin_data=admin_data)


@app.route('/hr/dashboard')
@role_required('HR Officer', 'Admin')
def hr_dashboard():
    """HR Dashboard - Employee management and approvals"""
    user = User.query.get(session['user_id'])
    
    # HR stats
    total_employees = User.query.filter_by(role='Employee').count()
    total_attendance_today = Attendance.query.filter_by(date=date.today()).count()
    pending_leaves = Leave.query.filter_by(status='Pending').count()
    
    hr_data = {
        'fullname': user.fullname,
        'login_id': user.login_id,
        'total_employees': total_employees,
        'total_attendance_today': total_attendance_today,
        'pending_leaves': pending_leaves
    }
    
    return render_template('hr_dashboard.html', user=session['user'], hr_data=hr_data)


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Force password change on first login (OLD USERS ONLY - New users use /set-password)"""
    user = User.query.get(session['user_id'])
    
    # If user needs OTP verification, redirect there first
    if not user.email_verified:
        return redirect(url_for('verify_otp'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate
        if not user.check_password(current_password):
            flash('Current password is incorrect.', 'error')
        elif len(new_password) < 8:
            flash('New password must be at least 8 characters long.', 'error')
        elif new_password != confirm_password:
            flash('New passwords do not match.', 'error')
        elif current_password == new_password:
            flash('New password must be different from current password.', 'error')
        else:
            user.set_password(new_password)
            user.is_first_login = False
            db.session.commit()
            
            session['is_first_login'] = False
            flash('Password changed successfully!', 'success')
            
            # Redirect based on role
            if user.role == 'Admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'HR Officer':
                return redirect(url_for('hr_dashboard'))
            else:
                return redirect(url_for('dashboard'))
    
    return render_template('change_password.html', user=user)


@app.route('/verify-otp', methods=['GET', 'POST'])
@login_required
def verify_otp():
    """Verify OTP sent to user's email"""
    user = User.query.get(session['user_id'])
    
    # If already verified, redirect to password setup
    if user.email_verified:
        if user.is_first_login:
            return redirect(url_for('set_new_password'))
        else:
            # Already verified and password set, go to dashboard
            if user.role == 'Admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'HR Officer':
                return redirect(url_for('hr_dashboard'))
            else:
                return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        otp_input = request.form.get('otp', '').strip()
        
        if not otp_input:
            flash('Please enter the OTP.', 'error')
        elif len(otp_input) != 6 or not otp_input.isdigit():
            flash('OTP must be 6 digits.', 'error')
        elif user.otp_attempts >= 5:
            flash('Too many failed attempts. Please request a new OTP.', 'error')
        elif not user.verify_otp(otp_input):
            db.session.commit()  # Save attempt count
            remaining = 5 - user.otp_attempts
            if remaining > 0:
                flash(f'Invalid or expired OTP. {remaining} attempts remaining.', 'error')
            else:
                flash('Too many failed attempts. Please request a new OTP.', 'error')
        else:
            # OTP verified successfully
            user.email_verified = True
            user.clear_otp()
            db.session.commit()
            
            flash('Email verified successfully!', 'success')
            return redirect(url_for('set_new_password'))
    
    return render_template('verify_otp.html', user=user, user_email=user.email)


@app.route('/resend-otp', methods=['POST'])
@login_required
def resend_otp():
    """Resend OTP to user's email"""
    user = User.query.get(session['user_id'])
    
    # Rate limiting: 60 seconds between requests
    if user.last_otp_request:
        time_since_last = (datetime.now() - user.last_otp_request).total_seconds()
        if time_since_last < 60:
            flash(f'Please wait {int(60 - time_since_last)} seconds before requesting a new OTP.', 'error')
            return redirect(url_for('verify_otp'))
    
    # Generate and send new OTP
    otp = generate_otp()
    user.set_otp(otp)
    
    if send_otp_email(user.email, user.fullname, user.login_id, otp):
        db.session.commit()
        flash('A new OTP has been sent to your email.', 'success')
    else:
        flash('Failed to send OTP. Please contact your administrator.', 'error')
    
    return redirect(url_for('verify_otp'))


@app.route('/set-password', methods=['GET', 'POST'])
@login_required
def set_new_password():
    """Set new password after OTP verification"""
    user = User.query.get(session['user_id'])
    
    # Check if OTP verified
    if not user.email_verified:
        flash('Please verify your email first.', 'error')
        return redirect(url_for('verify_otp'))
    
    # If password already set (not first login), redirect to dashboard
    if not user.is_first_login:
        if user.role == 'Admin':
            return redirect(url_for('admin_dashboard'))
        elif user.role == 'HR Officer':
            return redirect(url_for('hr_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate password strength
        is_valid, message = validate_password_strength(new_password)
        
        if not is_valid:
            flash(message, 'error')
        elif new_password != confirm_password:
            flash('Passwords do not match.', 'error')
        else:
            # Set new password
            user.set_password(new_password)
            user.is_first_login = False
            db.session.commit()
            
            session['is_first_login'] = False
            flash('Password set successfully! Welcome to Dayflow.', 'success')
            
            # Redirect based on role
            if user.role == 'Admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'HR Officer':
                return redirect(url_for('hr_dashboard'))
            else:
                return redirect(url_for('dashboard'))
    
    return render_template('set_password.html', user=user)


@app.route('/user-created')
@role_required('Admin', 'HR Officer')
def user_created():
    """Display newly created user credentials"""
    login_id = session.pop('new_user_login_id', None)
    temp_password = session.pop('new_user_temp_password', None)
    fullname = session.pop('new_user_fullname', None)
    
    if not login_id:
        return redirect(url_for('signup'))
    
    return render_template('user_created.html', 
                         login_id=login_id, 
                         temp_password=temp_password,
                         fullname=fullname)


@app.route('/unauthorized')
def unauthorized():
    """Unauthorized access page"""
    return render_template('unauthorized.html'), 403


def get_employee_status(user_id):
    """
    Compute employee attendance status for today
    Returns: 'present', 'on_leave', or 'absent'
    """
    today = date.today()
    
    # Check if on approved leave
    leave = Leave.query.filter(
        Leave.user_id == user_id,
        Leave.status == 'Approved',
        Leave.start_date <= today,
        Leave.end_date >= today
    ).first()
    
    if leave:
        return 'on_leave'
    
    # Check attendance
    attendance = Attendance.query.filter_by(user_id=user_id, date=today).first()
    
    if attendance and attendance.check_in:
        return 'present'
    
    return 'absent'


def get_salary_data(user_id):
    """Get salary data for user"""
    salary = Salary.query.filter_by(user_id=user_id).first()
    if salary:
        return salary.to_dict()
    return None


@app.route('/employees')
@login_required
def employees():
    """Employees directory page - Shows all employees with status indicators"""
    current_user = User.query.get(session['user_id'])
    
    if not current_user:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    
    # Get all users (employees for Employee role, all for Admin/HR)
    if current_user.role == 'Employee':
        # Employees can see all employees
        all_employees = User.query.all()
    else:
        # Admin and HR can see everyone
        all_employees = User.query.all()
    
    # Build employee data with status
    employees_data = []
    for emp in all_employees:
        status = get_employee_status(emp.id)
        
        # Get today's attendance for check-in info
        today_attendance = get_today_attendance(emp.id)
        
        employees_data.append({
            'id': emp.id,
            'fullname': emp.fullname,
            'login_id': emp.login_id,
            'email': emp.email,
            'role': emp.role,
            'status': status,
            'check_in_time': today_attendance.check_in.strftime('%I:%M %p') if today_attendance and today_attendance.check_in else None,
            'is_current_user': emp.id == current_user.id
        })
    
    # Get current user's attendance for check-in/out buttons
    today_record = get_today_attendance(current_user.id)
    action_state = build_action_state(today_record)
    
    return render_template('employees.html',
                         user=session['user'],
                         current_user=current_user,
                         employees=employees_data,
                         today_record=today_record,
                         action_state=action_state)


def summarize_attendance(record: Attendance | None):
    if not record:
        return {
            'date_label': date.today().strftime('%A, %b %d'),
            'status': 'Not Started',
            'check_in': '—',
            'check_out': '—',
            'duration': '—'
        }

    record.compute_status()
    return {
        'date_label': record.date.strftime('%A, %b %d'),
        'status': record.status,
        'check_in': record.check_in.strftime('%I:%M %p') if record.check_in else '—',
        'check_out': record.check_out.strftime('%I:%M %p') if record.check_out else '—',
        'duration': f"{record.duration_minutes // 60}h {record.duration_minutes % 60}m" if record.duration_minutes else '—'
    }


@app.route('/attendance')
@login_required
def attendance():
    """Attendance Tracking Page with Check-In/Check-Out"""
    if 'user_id' not in session:
        flash('Please login to access attendance.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('User not found. Please login again.', 'error')
        return redirect(url_for('login'))

    # Get today's attendance record
    today_record = get_today_attendance(user.id)
    
    # Build today's summary
    today_summary = summarize_attendance(today_record)
    
    # Build weekly overview
    weekly_overview = build_weekly_overview(user.id)
    
    # Build action state (can check in/out?)
    action_state = build_action_state(today_record)
    
    return render_template(
        'attendance.html',
        user=user,
        today_summary=today_summary,
        weekly_overview=weekly_overview,
        action_state=action_state
    )


@app.route('/attendance/list')
@login_required
def attendance_list():
    """Attendance List View - Role-based (Employee: Monthly | Admin/HR: Daily)"""
    if 'user_id' not in session:
        flash('Please login to access attendance.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('User not found. Please login again.', 'error')
        return redirect(url_for('login'))

    # Get query parameters
    view_date = request.args.get('date')
    view_month = request.args.get('month')
    search_query = request.args.get('search', '').strip()
    employee_id = request.args.get('employee_id')  # For admin/HR viewing specific employee

    # Role-based view logic
    if user.role in ['Admin', 'HR Officer']:
        # Check if viewing specific employee's monthly attendance
        if employee_id:
            try:
                view_employee = User.query.get(int(employee_id))
                if not view_employee:
                    flash('Employee not found.', 'error')
                    return redirect(url_for('attendance_list'))
                
                # Show monthly view for this employee
                if view_month:
                    try:
                        target_month = datetime.strptime(view_month, '%Y-%m').date()
                    except ValueError:
                        target_month = date.today().replace(day=1)
                else:
                    target_month = date.today().replace(day=1)

                # Get month range
                if target_month.month == 12:
                    next_month = target_month.replace(year=target_month.year + 1, month=1)
                else:
                    next_month = target_month.replace(month=target_month.month + 1)

                # Get all attendance records for the month for this employee
                records = Attendance.query.filter(
                    Attendance.user_id == view_employee.id,
                    Attendance.date >= target_month,
                    Attendance.date < next_month
                ).order_by(Attendance.date.desc()).all()

                # Get approved leaves for the month
                leaves = Leave.query.filter(
                    Leave.user_id == view_employee.id,
                    Leave.status == 'Approved',
                    Leave.start_date < next_month,
                    Leave.end_date >= target_month
                ).all()

                # Build leave dates set
                leave_dates = set()
                for leave in leaves:
                    current = max(leave.start_date, target_month)
                    end = min(leave.end_date, next_month - timedelta(days=1))
                    while current <= end:
                        leave_dates.add(current)
                        current += timedelta(days=1)

                # Build attendance data
                attendance_data = []
                days_present = 0
                total_working_days = 0
                
                current = target_month
                while current < next_month:
                    total_working_days += 1
                    
                    record = next((r for r in records if r.date == current), None)
                    
                    if current in leave_dates:
                        attendance_data.append({
                            'date': current.strftime('%d %b, %Y'),
                            'check_in': 'On Leave',
                            'check_out': '—',
                            'work_hours': '—',
                            'extra_hours': '—',
                            'status': 'On Leave'
                        })
                    elif record and record.check_in:
                        check_in_display = record.check_in.strftime('%I:%M %p')
                        
                        if record.check_out:
                            check_out_display = record.check_out.strftime('%I:%M %p')
                            total_minutes = int((record.check_out - record.check_in).total_seconds() / 60)
                            
                            hours = total_minutes // 60
                            minutes = total_minutes % 60
                            work_hours_display = f'{hours}h {minutes}m'
                            
                            if total_minutes > 480:
                                extra_minutes = total_minutes - 480
                                extra_h = extra_minutes // 60
                                extra_m = extra_minutes % 60
                                extra_hours_display = f'{extra_h}h {extra_m}m'
                            else:
                                extra_hours_display = '0h'
                            
                            status = 'Present'
                            days_present += 1
                        else:
                            check_out_display = '—'
                            work_hours_display = '—'
                            extra_hours_display = '—'
                            status = 'In Progress'

                        attendance_data.append({
                            'date': current.strftime('%d %b, %Y'),
                            'check_in': check_in_display,
                            'check_out': check_out_display,
                            'work_hours': work_hours_display,
                            'extra_hours': extra_hours_display,
                            'status': status
                        })
                    else:
                        attendance_data.append({
                            'date': current.strftime('%d %b, %Y'),
                            'check_in': '—',
                            'check_out': '—',
                            'work_hours': '—',
                            'extra_hours': '—',
                            'status': 'Absent'
                        })

                    current += timedelta(days=1)

                # Previous and next month navigation
                if target_month.month == 1:
                    prev_month = target_month.replace(year=target_month.year - 1, month=12)
                else:
                    prev_month = target_month.replace(month=target_month.month - 1)

                return render_template(
                    'attendance_list.html',
                    user=user,
                    view_type='employee_monthly',
                    view_employee=view_employee,
                    target_month=target_month,
                    attendance_data=attendance_data,
                    total_working_days=total_working_days,
                    days_present=days_present,
                    leaves_count=len(leave_dates),
                    prev_month=prev_month.strftime('%Y-%m'),
                    next_month=next_month.strftime('%Y-%m'),
                    current_month=target_month.strftime('%B %Y')
                )
            except ValueError:
                flash('Invalid employee ID.', 'error')
                return redirect(url_for('attendance_list'))
        
        # ADMIN/HR VIEW: Daily view of all employees
        if view_date:
            try:
                target_date = datetime.strptime(view_date, '%Y-%m-%d').date()
            except ValueError:
                target_date = date.today()
        else:
            target_date = date.today()

        # Get all employees
        employees_query = User.query
        
        # Apply search filter
        if search_query:
            employees_query = employees_query.filter(
                db.or_(
                    User.fullname.ilike(f'%{search_query}%'),
                    User.login_id.ilike(f'%{search_query}%')
                )
            )
        
        all_employees = employees_query.all()

        # Build attendance data for each employee
        attendance_data = []
        for emp in all_employees:
            record = Attendance.query.filter_by(user_id=emp.id, date=target_date).first()
            
            # Check for leave
            on_leave = Leave.query.filter(
                Leave.user_id == emp.id,
                Leave.status == 'Approved',
                Leave.start_date <= target_date,
                Leave.end_date >= target_date
            ).first()

            work_hours = 0
            extra_hours = 0
            status = 'Absent'
            check_in_display = '—'
            check_out_display = '—'
            work_hours_display = '—'
            extra_hours_display = '—'

            if on_leave:
                status = 'On Leave'
                check_in_display = 'On Leave'
            elif record and record.check_in:
                check_in_display = record.check_in.strftime('%I:%M %p')
                
                if record.check_out and record.check_out > record.check_in:
                    # Both check-in and check-out exist, and check-out is after check-in
                    check_out_display = record.check_out.strftime('%I:%M %p')
                    total_minutes = int((record.check_out - record.check_in).total_seconds() / 60)
                    work_hours = total_minutes / 60
                    
                    # Display work hours as "7h 32m"
                    hours = total_minutes // 60
                    minutes = total_minutes % 60
                    work_hours_display = f'{hours}h {minutes}m'
                    
                    # Extra hours = hours beyond 8
                    if work_hours > 8:
                        extra_hours = work_hours - 8
                        extra_hours_minutes = int(extra_hours * 60)
                        extra_h = extra_hours_minutes // 60
                        extra_m = extra_hours_minutes % 60
                        extra_hours_display = f'{extra_h}h {extra_m}m'
                    else:
                        extra_hours_display = '0h'
                    
                    # Determine status based on work hours
                    if total_minutes >= 8 * 60:  # 8 hours or more
                        status = 'Present'
                    elif total_minutes >= 4 * 60:  # 4-8 hours
                        status = 'Half Day'
                    else:  # Less than 4 hours
                        status = 'Short Shift'
                else:
                    # Checked in but not checked out yet
                    check_out_display = '—'
                    status = 'In Progress'

            attendance_data.append({
                'employee_name': emp.fullname,
                'login_id': emp.login_id,
                'check_in': check_in_display,
                'check_out': check_out_display,
                'work_hours': work_hours_display,
                'extra_hours': extra_hours_display,
                'status': status
            })

        return render_template(
            'attendance_list.html',
            user=user,
            view_type='daily',
            target_date=target_date,
            attendance_data=attendance_data,
            search_query=search_query,
            prev_date=(target_date - timedelta(days=1)).strftime('%Y-%m-%d'),
            next_date=(target_date + timedelta(days=1)).strftime('%Y-%m-%d')
        )

    else:
        # EMPLOYEE VIEW: Monthly view of own attendance
        if view_month:
            try:
                target_month = datetime.strptime(view_month, '%Y-%m').date()
            except ValueError:
                target_month = date.today().replace(day=1)
        else:
            target_month = date.today().replace(day=1)

        # Get month range
        if target_month.month == 12:
            next_month = target_month.replace(year=target_month.year + 1, month=1)
        else:
            next_month = target_month.replace(month=target_month.month + 1)

        # Get all attendance records for the month
        records = Attendance.query.filter(
            Attendance.user_id == user.id,
            Attendance.date >= target_month,
            Attendance.date < next_month
        ).order_by(Attendance.date.desc()).all()

        # Get leaves for the month
        leaves = Leave.query.filter(
            Leave.user_id == user.id,
            Leave.status == 'Approved',
            db.or_(
                db.and_(Leave.start_date >= target_month, Leave.start_date < next_month),
                db.and_(Leave.end_date >= target_month, Leave.end_date < next_month),
                db.and_(Leave.start_date < target_month, Leave.end_date >= next_month)
            )
        ).all()

        # Build date-to-leave mapping
        leave_dates = set()
        for leave in leaves:
            current = max(leave.start_date, target_month)
            end = min(leave.end_date, next_month - timedelta(days=1))
            while current <= end:
                leave_dates.add(current)
                current += timedelta(days=1)

        # Build attendance data
        attendance_data = []
        total_working_days = 0
        days_present = 0
        
        # Generate all dates in month
        current = target_month
        while current < next_month:
            total_working_days += 1
            
            record = next((r for r in records if r.date == current), None)
            is_leave = current in leave_dates

            work_hours = 0
            extra_hours = 0
            check_in_display = '—'
            check_out_display = '—'
            work_hours_display = '—'
            extra_hours_display = '—'
            status = 'Absent'

            if is_leave:
                attendance_data.append({
                    'date': current.strftime('%d %b, %Y'),
                    'check_in': 'On Leave',
                    'check_out': '—',
                    'work_hours': '—',
                    'extra_hours': '—',
                    'status': 'Leave'
                })
                days_present += 1  # Leave counts as present
            elif record and record.check_in:
                check_in_display = record.check_in.strftime('%I:%M %p')
                
                if record.check_out and record.check_out > record.check_in:
                    # Both check-in and check-out exist, and check-out is after check-in
                    check_out_display = record.check_out.strftime('%I:%M %p')
                    total_minutes = int((record.check_out - record.check_in).total_seconds() / 60)
                    
                    # Display work hours as "7h 32m"
                    hours = total_minutes // 60
                    minutes = total_minutes % 60
                    work_hours_display = f'{hours}h {minutes}m'
                    
                    # Extra hours = hours beyond 8 (480 minutes)
                    if total_minutes > 480:
                        extra_minutes = total_minutes - 480
                        extra_h = extra_minutes // 60
                        extra_m = extra_minutes % 60
                        extra_hours_display = f'{extra_h}h {extra_m}m'
                    else:
                        extra_hours_display = '0h'
                    
                    status = 'Present'
                    days_present += 1
                else:
                    # Checked in but not checked out yet
                    check_out_display = '—'
                    status = 'In Progress'
                    # Don't count as present until checked out

                attendance_data.append({
                    'date': current.strftime('%d %b, %Y'),
                    'check_in': check_in_display,
                    'check_out': check_out_display,
                    'work_hours': work_hours_display,
                    'extra_hours': extra_hours_display,
                    'status': status
                })
            else:
                attendance_data.append({
                    'date': current.strftime('%d %b, %Y'),
                    'check_in': '—',
                    'check_out': '—',
                    'work_hours': '—',
                    'extra_hours': '—',
                    'status': 'Absent'
                })

            current += timedelta(days=1)

        # Previous and next month navigation
        if target_month.month == 1:
            prev_month = target_month.replace(year=target_month.year - 1, month=12)
        else:
            prev_month = target_month.replace(month=target_month.month - 1)

        return render_template(
            'attendance_list.html',
            user=user,
            view_type='monthly',
            target_month=target_month,
            attendance_data=attendance_data,
            total_working_days=total_working_days,
            days_present=days_present,
            leaves_count=len(leave_dates),
            prev_month=prev_month.strftime('%Y-%m'),
            next_month=next_month.strftime('%Y-%m'),
            current_month=target_month.strftime('%B %Y')
        )


@app.route('/attendance/check-in', methods=['POST'])
@login_required
def attendance_check_in():
    """Check-in endpoint for employees"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    user_id = session['user_id']
    today_record = get_today_attendance(user_id)

    if today_record and today_record.check_in:
        return jsonify({'success': False, 'message': 'Already checked in today.'}), 400

    now = datetime.now()
    if not today_record:
        today_record = Attendance(user_id=user_id, date=date.today())
        db.session.add(today_record)

    today_record.check_in = now
    today_record.compute_status()
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Checked in successfully.',
        'check_in_time': now.strftime('%I:%M:%S %p'),
        'timestamp': now.isoformat()
    })


@app.route('/attendance/check-out', methods=['POST'])
@login_required
def attendance_check_out():
    """Check-out endpoint for employees"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    user_id = session['user_id']
    today_record = get_today_attendance(user_id)

    if not today_record or not today_record.check_in:
        return jsonify({'success': False, 'message': 'You need to check in first.'}), 400

    if today_record.check_out:
        return jsonify({'success': False, 'message': 'Already checked out today.'}), 400

    now = datetime.now()
    today_record.check_out = now
    today_record.compute_status()
    db.session.commit()

    # Calculate duration
    duration = now - today_record.check_in
    total_minutes = int(duration.total_seconds() / 60)
    hours = total_minutes // 60
    minutes = total_minutes % 60

    return jsonify({
        'success': True,
        'message': 'Checked out successfully.',
        'check_out_time': now.strftime('%I:%M:%S %p'),
        'duration': f'{hours}h {minutes}m',
        'status': today_record.status
    })


@app.route('/employee/leave')
@login_required
def employee_leave():
    """Employee leave management page"""
    if 'user_id' not in session:
        flash('Please login to access leave management.', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('User not found. Please login again.', 'error')
        return redirect(url_for('login'))
    
    return render_template('leave.html', user=session['user'])


@app.route('/logout')
def logout():
    """Logout route"""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/profile')
@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id=None):
    """User profile page with edit permissions"""
    viewer = User.query.get(session['user_id'])
    if not viewer:
        session.clear()
        flash('Please login again.', 'error')
        return redirect(url_for('login'))
    
    # Determine which user profile to show
    if user_id is None:
        # Viewing own profile
        user = viewer
        is_self_view = True
        editable = True
    else:
        # Viewing another user's profile
        user = User.query.get(user_id)
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('employees'))
        is_self_view = (user.id == viewer.id)
        # Admin/HR can view others but with different edit permissions
        editable = is_self_view or viewer.role in ['Admin', 'HR Officer']
    
    # Determine if viewer is HR/Admin
    is_hr_admin_viewer = viewer.role in ['Admin', 'HR Officer']
    
    # Determine dashboard URL based on viewer role
    if viewer.role == 'Admin':
        dashboard_url = url_for('admin_dashboard')
    elif viewer.role == 'HR Officer':
        dashboard_url = url_for('hr_dashboard')
    else:
        dashboard_url = url_for('dashboard')
    
    # Get salary data if HR/Admin viewing employee profile
    salary_data = None
    if is_hr_admin_viewer and user.role == 'Employee':
        salary_data = get_salary_data(user.id)
    
    return render_template('profile.html', 
                         user=user, 
                         viewer=viewer,
                         editable=editable,
                         is_self_view=is_self_view,
                         is_hr_admin_viewer=is_hr_admin_viewer,
                         dashboard_url=dashboard_url,
                         salary_data=salary_data)


@app.route('/employee/<int:employee_id>')
@login_required
def view_employee(employee_id):
    """View employee profile - Read-only mode"""
    current_user = User.query.get(session['user_id'])
    if not current_user:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    
    employee = User.query.get(employee_id)
    if not employee:
        flash('Employee not found.', 'error')
        return redirect(url_for('employees'))
    
    # Get employee's attendance status
    status = get_employee_status(employee.id)
    today_attendance = get_today_attendance(employee.id)
    
    employee_data = {
        'id': employee.id,
        'fullname': employee.fullname,
        'login_id': employee.login_id,
        'email': employee.email,
        'role': employee.role,
        'year_of_joining': employee.year_of_joining,
        'created_at': employee.created_at,
        'status': status,
        'check_in_time': today_attendance.check_in.strftime('%I:%M %p') if today_attendance and today_attendance.check_in else None,
        'check_out_time': today_attendance.check_out.strftime('%I:%M %p') if today_attendance and today_attendance.check_out else None
    }
    
    return render_template('employee_view.html', employee=employee_data, editable=False)


# ============= LEAVE MANAGEMENT ROUTES =============

@app.route('/leave/apply', methods=['GET', 'POST'])
@login_required
def apply_leave():
    """Employee leave application - EMPLOYEES ONLY"""
    current_user = User.query.get(session['user_id'])
    if not current_user:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    
    # Block Admin and HR Officer from applying leave
    if current_user.role in ['Admin', 'HR Officer']:
        flash('Admin and HR Officer cannot apply for leave from this portal.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        leave_type = request.form.get('leave_type')
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
        remarks = request.form.get('remarks', '').strip()
        
        # Validation
        if not leave_type or leave_type not in ['Paid Leave', 'Sick Leave', 'Unpaid Leave']:
            flash('Please select a valid leave type.', 'error')
            return redirect(url_for('apply_leave'))
        
        if not start_date_str or not end_date_str:
            flash('Please select both start and end dates.', 'error')
            return redirect(url_for('apply_leave'))
        
        if not remarks or len(remarks) > 250:
            flash('Remarks are required (max 250 characters).', 'error')
            return redirect(url_for('apply_leave'))
        
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format.', 'error')
            return redirect(url_for('apply_leave'))
        
        # End date must not be before start date
        if end_date < start_date:
            flash('End date cannot be before start date.', 'error')
            return redirect(url_for('apply_leave'))
        
        # Calculate total days (inclusive)
        total_days = (end_date - start_date).days + 1
        
        # Create leave request
        new_leave = Leave(
            user_id=current_user.id,
            leave_type=leave_type,
            start_date=start_date,
            end_date=end_date,
            total_days=total_days,
            reason=remarks,
            status='Pending'
        )
        
        db.session.add(new_leave)
        db.session.commit()
        
        flash('Leave request submitted successfully. Status: Pending.', 'success')
        return redirect(url_for('my_leave_requests'))
    
    return render_template('apply_leave.html', user=current_user)


@app.route('/leave/my-requests')
@login_required
def my_leave_requests():
    """Employee leave requests view - EMPLOYEES ONLY"""
    current_user = User.query.get(session['user_id'])
    if not current_user:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    
    # Block Admin and HR Officer
    if current_user.role in ['Admin', 'HR Officer']:
        flash('Please use the Leave Management page to view all requests.', 'error')
        return redirect(url_for('leave_management'))
    
    # Get all leave requests for the current user, ordered by most recent
    leaves = Leave.query.filter_by(user_id=current_user.id).order_by(Leave.applied_on.desc()).all()
    
    # Calculate allocation summary for current year
    current_year = datetime.now().year
    year_start = datetime(current_year, 1, 1).date()
    
    # Calculate days used per leave type (approved leaves only)
    paid_used = db.session.query(db.func.sum(Leave.total_days)).filter(
        Leave.user_id == current_user.id,
        Leave.leave_type.in_(['Paid Time Off', 'Paid Leave']),
        Leave.status == 'Approved',
        Leave.start_date >= year_start
    ).scalar() or 0
    
    sick_used = db.session.query(db.func.sum(Leave.total_days)).filter(
        Leave.user_id == current_user.id,
        Leave.leave_type == 'Sick Leave',
        Leave.status == 'Approved',
        Leave.start_date >= year_start
    ).scalar() or 0
    
    # Standard allocation (can be customized per user in future)
    paid_allocated = 20
    sick_allocated = 10
    
    allocation = {
        'paid_time_off': {
            'allocated': paid_allocated,
            'used': paid_used,
            'available': paid_allocated - paid_used
        },
        'sick_leave': {
            'allocated': sick_allocated,
            'used': sick_used,
            'available': sick_allocated - sick_used
        }
    }
    
    return render_template('my_leave_requests.html', user=current_user, leaves=leaves, allocation=allocation)


@app.route('/leave/manage')
@login_required
def leave_management():
    """Admin/HR leave management view - ADMIN & HR ONLY"""
    current_user = User.query.get(session['user_id'])
    if not current_user:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    
    # Only Admin and HR Officer can access
    if current_user.role not in ['Admin', 'HR Officer']:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get all leave requests with user details, ordered by status and date
    leaves = db.session.query(Leave, User).join(User, Leave.user_id == User.id).order_by(
        db.case(
            (Leave.status == 'Pending', 1),
            (Leave.status == 'Approved', 2),
            (Leave.status == 'Rejected', 3)
        ),
        Leave.applied_on.desc()
    ).all()
    
    # Calculate organization-wide statistics for current year
    current_year = datetime.now().year
    year_start = datetime(current_year, 1, 1).date()
    
    # Total pending requests
    pending_count = Leave.query.filter(
        Leave.status == 'Pending',
        Leave.start_date >= year_start
    ).count()
    
    # Total approved days this year
    total_approved_days = db.session.query(db.func.sum(Leave.total_days)).filter(
        Leave.status == 'Approved',
        Leave.start_date >= year_start
    ).scalar() or 0
    
    # Employees on leave today
    today = datetime.now().date()
    on_leave_today = Leave.query.filter(
        Leave.status == 'Approved',
        Leave.start_date <= today,
        Leave.end_date >= today
    ).count()
    
    stats = {
        'pending_requests': pending_count,
        'approved_days': total_approved_days,
        'on_leave_today': on_leave_today
    }
    
    return render_template('leave_management.html', user=current_user, leaves=leaves, stats=stats)


@app.route('/leave/approve/<int:leave_id>', methods=['POST'])
@login_required
def approve_leave(leave_id):
    """Approve leave request - ADMIN & HR ONLY"""
    current_user = User.query.get(session['user_id'])
    if not current_user:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    # Only Admin and HR Officer can approve
    if current_user.role not in ['Admin', 'HR Officer']:
        return jsonify({'success': False, 'message': 'You do not have permission to approve leave requests.'}), 403
    
    leave = Leave.query.get(leave_id)
    if not leave:
        return jsonify({'success': False, 'message': 'Leave request not found.'}), 404
    
    # Only Pending requests can be approved
    if leave.status != 'Pending':
        return jsonify({'success': False, 'message': f'Cannot approve a {leave.status} request.'}), 400
    
    # Get optional comment
    data = request.get_json() or {}
    admin_comment = data.get('comment', '').strip()
    
    # Update leave status
    leave.status = 'Approved'
    leave.admin_comment = admin_comment if admin_comment else None
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Leave request approved successfully.',
        'leave_id': leave.id,
        'status': 'Approved'
    })


@app.route('/leave/reject/<int:leave_id>', methods=['POST'])
@login_required
def reject_leave(leave_id):
    """Reject leave request - ADMIN & HR ONLY"""
    current_user = User.query.get(session['user_id'])
    if not current_user:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    # Only Admin and HR Officer can reject
    if current_user.role not in ['Admin', 'HR Officer']:
        return jsonify({'success': False, 'message': 'You do not have permission to reject leave requests.'}), 403
    
    leave = Leave.query.get(leave_id)
    if not leave:
        return jsonify({'success': False, 'message': 'Leave request not found.'}), 404
    
    # Only Pending requests can be rejected
    if leave.status != 'Pending':
        return jsonify({'success': False, 'message': f'Cannot reject a {leave.status} request.'}), 400
    
    # Get mandatory rejection comment
    data = request.get_json() or {}
    admin_comment = data.get('comment', '').strip()
    
    if not admin_comment:
        return jsonify({'success': False, 'message': 'Rejection comment is required.'}), 400
    
    # Update leave status
    leave.status = 'Rejected'
    leave.admin_comment = admin_comment
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Leave request rejected.',
        'leave_id': leave.id,
        'status': 'Rejected'
    })


# ============= PROFILE MANAGEMENT ROUTES =============

@app.route('/profile/update/<int:user_id>', methods=['POST'])
@login_required
def update_profile(user_id):
    """Update user profile information"""
    viewer = User.query.get(session['user_id'])
    user = User.query.get(user_id)
    
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('employees'))
    
    # Permission check
    is_self = (user.id == viewer.id)
    is_hr_admin = viewer.role in ['Admin', 'HR Officer']
    
    if not (is_self or is_hr_admin):
        flash('You do not have permission to edit this profile.', 'error')
        return redirect(url_for('profile'))
    
    try:
        # Fields everyone can edit on their own profile
        if is_self:
            user.fullname = request.form.get('fullname', user.fullname)
            user.email = request.form.get('email', user.email)
            user.newsletter = 'newsletter' in request.form
        
        # Fields only HR/Admin can edit
        if is_hr_admin:
            user.fullname = request.form.get('fullname', user.fullname)
            user.email = request.form.get('email', user.email)
            user.newsletter = 'newsletter' in request.form
            user.department = request.form.get('department', user.department)
            user.designation = request.form.get('designation', user.designation)
            user.reporting_manager = request.form.get('reporting_manager', user.reporting_manager)
            
            date_of_joining_str = request.form.get('date_of_joining')
            if date_of_joining_str:
                user.date_of_joining = datetime.strptime(date_of_joining_str, '%Y-%m-%d').date()
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating profile: {str(e)}', 'error')
    
    return redirect(url_for('profile', user_id=user_id if not is_self else None))


@app.route('/profile/upload-photo/<int:user_id>', methods=['POST'])
@login_required
def upload_profile_photo(user_id):
    """Upload profile photo with cropping support"""
    viewer = User.query.get(session['user_id'])
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # Permission check
    is_self = (user.id == viewer.id)
    is_hr_admin = viewer.role in ['Admin', 'HR Officer']
    
    if not (is_self or is_hr_admin):
        return jsonify({'success': False, 'message': 'Permission denied'}), 403
    
    if 'photo' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400
    
    file = request.files['photo']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    # Check file type
    allowed_extensions = {'png', 'jpg', 'jpeg', 'webp'}
    file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    
    if file_ext not in allowed_extensions:
        return jsonify({'success': False, 'message': 'Invalid file type. Use PNG, JPG, or WEBP'}), 400
    
    # Check file size (2MB max)
    file.seek(0, 2)  # Seek to end
    file_size = file.tell()
    file.seek(0)  # Reset to start
    
    if file_size > 2 * 1024 * 1024:  # 2MB
        return jsonify({'success': False, 'message': 'File too large. Max 2MB'}), 400
    
    try:
        # Save file
        filename = f"profile_{user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_ext}"
        upload_dir = os.path.join('static', 'uploads', 'profiles')
        os.makedirs(upload_dir, exist_ok=True)
        
        file_path = os.path.join(upload_dir, filename)
        file.save(file_path)
        
        # Update user profile
        old_photo = user.profile_photo
        user.profile_photo = f"uploads/profiles/{filename}"
        db.session.commit()
        
        # Delete old photo if exists
        if old_photo and os.path.exists(os.path.join('static', old_photo)):
            try:
                os.remove(os.path.join('static', old_photo))
            except:
                pass
        
        return jsonify({
            'success': True,
            'message': 'Profile photo updated successfully',
            'photo_url': url_for('static', filename=user.profile_photo)
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Upload failed: {str(e)}'}), 500


@app.route('/profile/upload-resume/<int:user_id>', methods=['POST'])
@login_required
def upload_resume(user_id):
    """Upload resume file (PDF/DOC/DOCX)"""
    viewer = User.query.get(session['user_id'])
    user = User.query.get(user_id)
    
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('employees'))
    
    # Permission check
    is_self = (user.id == viewer.id)
    is_hr_admin = viewer.role in ['Admin', 'HR Officer']
    
    if not (is_self or is_hr_admin):
        flash('Permission denied.', 'error')
        return redirect(url_for('profile'))
    
    if 'resume' not in request.files:
        flash('No file uploaded.', 'error')
        return redirect(url_for('profile', user_id=user_id if not is_self else None))
    
    file = request.files['resume']
    if file.filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('profile', user_id=user_id if not is_self else None))
    
    # Check file type
    allowed_extensions = {'pdf', 'doc', 'docx'}
    file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    
    if file_ext not in allowed_extensions:
        flash('Invalid file type. Use PDF, DOC, or DOCX only.', 'error')
        return redirect(url_for('profile', user_id=user_id if not is_self else None))
    
    # Check file size (5MB max)
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    
    if file_size > 5 * 1024 * 1024:  # 5MB
        flash('File too large. Maximum 5MB allowed.', 'error')
        return redirect(url_for('profile', user_id=user_id if not is_self else None))
    
    try:
        # Save file
        filename = f"resume_{user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_ext}"
        upload_dir = os.path.join('static', 'uploads', 'resumes')
        os.makedirs(upload_dir, exist_ok=True)
        
        file_path = os.path.join(upload_dir, filename)
        file.save(file_path)
        
        # Update user profile
        old_resume = user.resume_file
        user.resume_file = f"uploads/resumes/{filename}"
        db.session.commit()
        
        # Delete old resume if exists
        if old_resume and os.path.exists(os.path.join('static', old_resume)):
            try:
                os.remove(os.path.join('static', old_resume))
            except:
                pass
        
        flash('Resume uploaded successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Upload failed: {str(e)}', 'error')
    
    return redirect(url_for('profile', user_id=user_id if not is_self else None))


@app.route('/profile/salary/<int:user_id>', methods=['POST'])
@role_required('Admin', 'HR Officer')
def update_salary(user_id):
    """Update salary information (HR/Admin only)"""
    user = User.query.get(user_id)
    
    if not user or user.role != 'Employee':
        flash('Invalid user.', 'error')
        return redirect(url_for('employees'))
    
    try:
        monthly_wage = float(request.form.get('monthly_wage', 0))
        
        # Get or create salary record
        salary = Salary.query.filter_by(user_id=user_id).first()
        if not salary:
            salary = Salary(user_id=user_id)
            db.session.add(salary)
        
        # Update wage details
        salary.monthly_wage = monthly_wage
        salary.working_days_per_week = int(request.form.get('working_days_per_week', 5))
        salary.daily_working_hours = float(request.form.get('daily_hours', 8.0))
        salary.break_time_hours = float(request.form.get('break_hours', 1.0))
        
        # Update PF percentages
        salary.employee_pf_percent = float(request.form.get('employee_pf_percent', 12.0))
        salary.employer_pf_percent = float(request.form.get('employer_pf_percent', 12.0))
        
        # Update tax
        salary.professional_tax = float(request.form.get('professional_tax', 200.0))
        
        # Calculate all breakdowns
        salary.calculate_breakdown()
        
        db.session.commit()
        flash('Salary information updated successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating salary: {str(e)}', 'error')
    
    return redirect(url_for('profile', user_id=user_id))


@app.route('/management-action/<int:user_id>', methods=['POST'])
@role_required('Admin', 'HR Officer')
def management_action(user_id):
    """Handle management actions on employee profiles"""
    viewer = User.query.get(session['user_id'])
    user = User.query.get(user_id)
    
    if not user or user.id == viewer.id:
        flash('Invalid user.', 'error')
        return redirect(url_for('employees'))
    
    action = request.form.get('action')
    
    try:
        if action == 'assign_role' and viewer.role == 'Admin':
            new_role = request.form.get('new_role')
            if new_role in ['Employee', 'HR Officer']:
                user.role = new_role
                flash(f'Role updated to {new_role}.', 'success')
        
        elif action == 'toggle_active':
            user.is_active = not user.is_active
            status = 'activated' if user.is_active else 'deactivated'
            flash(f'Employee {status} successfully.', 'success')
        
        elif action == 'reset_password':
            new_temp_password = generate_temp_password()
            user.set_password(new_temp_password)
            user.is_first_login = True
            user.password_updated_at = datetime.utcnow()
            
            # Store in session to display
            session['reset_password_login_id'] = user.login_id or user.username
            session['reset_password_temp'] = new_temp_password
            session['reset_password_user'] = user.fullname
            
            flash('Password reset successfully. Temporary credentials generated.', 'success')
            db.session.commit()
            return redirect(url_for('password_reset_success'))
        
        else:
            flash('Invalid action.', 'error')
            return redirect(url_for('profile', user_id=user_id))
        
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        flash(f'Action failed: {str(e)}', 'error')
    
    return redirect(url_for('profile', user_id=user_id))


@app.route('/password-reset-success')
@role_required('Admin', 'HR Officer')
def password_reset_success():
    """Display temporary password after reset"""
    login_id = session.pop('reset_password_login_id', None)
    temp_password = session.pop('reset_password_temp', None)
    fullname = session.pop('reset_password_user', None)
    
    if not login_id or not temp_password:
        flash('No reset information found.', 'error')
        return redirect(url_for('employees'))
    
    return render_template('user_created.html',
                         login_id=login_id,
                         temp_password=temp_password,
                         fullname=fullname)


@app.errorhandler(404)
def page_not_found(e):
    """404 error handler"""
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

