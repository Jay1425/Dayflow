from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, date, timedelta
from functools import wraps
from sqlalchemy import text
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


def generate_reset_token():
    """Generate a secure password reset token"""
    return secrets.token_urlsafe(32)


def send_password_reset_email(email, fullname, reset_token):
    """Send password reset email with reset link"""
    try:
        print(f"📧 Sending password reset email to: {email}")
        
        # Generate reset link
        reset_link = url_for('reset_password', token=reset_token, _external=True)
        
        msg = Message(
            subject='Dayflow HRMS - Password Reset Request',
            recipients=[email]
        )
        
        msg.html = f'''
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0; text-align: center;">
                <h1 style="color: white; margin: 0;">🔐 Password Reset Request</h1>
            </div>
            
            <div style="background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px;">
                <p style="font-size: 16px; color: #333;">Hi <strong>{fullname}</strong>,</p>
                
                <p style="color: #666;">We received a request to reset your Dayflow HRMS account password.</p>
                
                <div style="background: #fff3cd; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ffc107;">
                    <p style="margin: 0; color: #856404;"><strong>⚠️ Important:</strong></p>
                    <p style="color: #856404; margin: 10px 0;">If you didn't request this password reset, please ignore this email or contact your administrator immediately.</p>
                </div>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_link}" style="display: inline-block; padding: 15px 40px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px;">
                        Reset Your Password
                    </a>
                </div>
                
                <div style="background: #e3f2fd; padding: 15px; border-radius: 8px; margin: 20px 0;">
                    <p style="color: #1976d2; margin: 0; font-size: 14px;"><strong>⏱️ This link expires in 1 hour</strong></p>
                    <p style="color: #666; margin: 10px 0; font-size: 12px;">For security reasons, this password reset link will only be valid for one hour.</p>
                </div>
                
                <div style="background: white; padding: 15px; border-radius: 8px; margin: 20px 0; border: 1px solid #e0e0e0;">
                    <p style="color: #666; margin: 0; font-size: 12px;">If the button doesn't work, copy and paste this link into your browser:</p>
                    <p style="color: #667eea; margin: 10px 0; font-size: 12px; word-break: break-all;">{reset_link}</p>
                </div>
                
                <p style="color: #999; font-size: 12px; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
                    <strong>Security Note:</strong> Never share your password reset link with anyone. Dayflow staff will never ask for your password or reset link.
                </p>
            </div>
        </body>
        </html>
        '''
        
        mail.send(msg)
        print(f"✅ Password reset email sent successfully to {email}")
        return True
    except Exception as e:
        print(f"❌ Password reset email sending failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


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
                        <li>Login with your <strong>Login ID</strong> and the password you created</li>
                        <li>Verify your email by entering the OTP code above</li>
                        <li>Once verified, you can access your account</li>
                        <li>Note: Employee registrations require HR approval</li>
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
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=True)  # Link to Company table
    registration_approved = db.Column(db.Boolean, default=False)  # For employee approval workflow
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # HR who approved
    approved_at = db.Column(db.DateTime, nullable=True)
    year_of_joining = db.Column(db.Integer, nullable=True)
    is_first_login = db.Column(db.Boolean, default=True)
    email_verified = db.Column(db.Boolean, default=False)  # Email OTP verification status
    otp = db.Column(db.String(6), nullable=True)  # Current OTP
    otp_expiry = db.Column(db.DateTime, nullable=True)  # OTP expiration time
    otp_attempts = db.Column(db.Integer, default=0)  # Track failed OTP attempts
    last_otp_request = db.Column(db.DateTime, nullable=True)  # Rate limiting
    reset_token = db.Column(db.String(100), nullable=True)  # Password reset token
    reset_token_expiry = db.Column(db.DateTime, nullable=True)  # Reset token expiration
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
    break_minutes = db.Column(db.Integer, default=60)  # Default 1 hour break
    status = db.Column(db.String(50), default='Absent')
    duration_minutes = db.Column(db.Integer, default=0)
    work_hours = db.Column(db.Float, default=0.0)  # Work hours (total - break)
    extra_hours = db.Column(db.Float, default=0.0)  # Extra hours beyond 8

    __table_args__ = (db.UniqueConstraint('user_id', 'date', name='uq_user_date'),)

    def compute_status(self):
        """
        Calculate work hours and status with break time consideration
        Formula: Work Hours = (CheckOut - CheckIn) - Break Time
        Extra Hours = max(Work Hours - 8, 0)
        """
        if self.check_in and self.check_out:
            # Total time in minutes
            total_minutes = int((self.check_out - self.check_in).total_seconds() // 60)
            self.duration_minutes = total_minutes
            
            # Work hours (subtract break time)
            work_minutes = max(0, total_minutes - (self.break_minutes or 0))
            self.work_hours = round(work_minutes / 60, 2)
            
            # Extra hours beyond 8-hour standard
            self.extra_hours = max(0, round((work_minutes - 480) / 60, 2))
            
            # Status determination
            if work_minutes >= 8 * 60:
                self.status = 'Present'
            elif work_minutes >= 4 * 60:
                self.status = 'Half Day'
            else:
                self.status = 'Short Shift'
        elif self.check_in and not self.check_out:
            self.status = 'In Progress'
            self.work_hours = 0.0
            self.extra_hours = 0.0
        else:
            self.status = 'Absent'
            self.work_hours = 0.0
            self.extra_hours = 0.0
        return self.status

    def to_dict(self):
        return {
            'date': self.date.isoformat(),
            'check_in': self.check_in.isoformat() if self.check_in else None,
            'check_out': self.check_out.isoformat() if self.check_out else None,
            'break_minutes': self.break_minutes,
            'work_hours': self.work_hours,
            'extra_hours': self.extra_hours,
            'status': self.status,
            'duration_minutes': self.duration_minutes
        }


class Company(db.Model):
    """Company/Organization Model for multi-tenant support"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    company_code = db.Column(db.String(10), unique=True, nullable=False)  # e.g., DF, OD
    description = db.Column(db.Text, nullable=True)
    industry = db.Column(db.String(100), nullable=True)
    address = db.Column(db.Text, nullable=True)
    website = db.Column(db.String(200), nullable=True)
    contact_email = db.Column(db.String(120), nullable=True)
    contact_phone = db.Column(db.String(20), nullable=True)
    logo_url = db.Column(db.String(200), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    def __repr__(self):
        return f'<Company {self.name}>'


class Leave(db.Model):
    """Leave/Time-Off Request Model with Payroll Integration"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Leave Type Configuration
    leave_type = db.Column(db.String(50), nullable=False)  # PAID, SICK, UNPAID
    is_paid = db.Column(db.Boolean, default=True)  # Affects payroll calculation
    
    # Date Range
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    total_days = db.Column(db.Integer, nullable=False)  # Working days count
    
    # Request Details
    reason = db.Column(db.Text, nullable=False)
    attachment_file = db.Column(db.String(200), nullable=True)  # For sick leave medical certificate
    
    # Status Lifecycle: PENDING → APPROVED/REJECTED
    status = db.Column(db.String(20), default='Pending')  # Pending, Approved, Rejected
    
    # Approval/Rejection Details
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Admin/HR who approved
    reviewed_at = db.Column(db.DateTime, nullable=True)
    admin_comment = db.Column(db.Text, nullable=True)  # Rejection reason or notes
    
    # Audit Trail
    applied_on = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Payroll Integration Flag
    is_locked = db.Column(db.Boolean, default=False)  # Locked after payroll generation
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('leave_requests', lazy=True))
    reviewer = db.relationship('User', foreign_keys=[reviewed_by], backref=db.backref('reviewed_leaves', lazy=True))
    
    @staticmethod
    def get_leave_type_config(leave_type):
        """Get configuration for leave type"""
        configs = {
            'PAID': {
                'name': 'Paid Time Off',
                'is_paid': True,
                'requires_attachment': False,
                'affects_payroll': False,
                'max_days': 12,  # 12 days per year
                'icon': 'fa-calendar',
                'color': 'green'
            },
            'SICK': {
                'name': 'Sick Leave',
                'is_paid': True,
                'requires_attachment': True,
                'affects_payroll': False,
                'max_days': 7,  # 7 days per year
                'icon': 'fa-notes-medical',
                'color': 'blue'
            },
            'UNPAID': {
                'name': 'Unpaid Leave',
                'is_paid': False,
                'requires_attachment': False,
                'affects_payroll': True,
                'max_days': None,  # Unlimited
                'icon': 'fa-calendar-times',
                'color': 'yellow'
            }
        }
        return configs.get(leave_type, configs['PAID'])
    
    def to_dict(self):
        config = self.get_leave_type_config(self.leave_type)
        return {
            'id': self.id,
            'leave_type': self.leave_type,
            'leave_type_name': config['name'],
            'is_paid': self.is_paid,
            'start_date': self.start_date.isoformat(),
            'end_date': self.end_date.isoformat(),
            'total_days': self.total_days,
            'reason': self.reason,
            'attachment_file': self.attachment_file,
            'status': self.status,
            'admin_comment': self.admin_comment,
            'applied_on': self.applied_on.strftime('%b %d, %Y %I:%M %p'),
            'reviewed_by': self.reviewer.fullname if self.reviewer else None,
            'reviewed_at': self.reviewed_at.strftime('%b %d, %Y %I:%M %p') if self.reviewed_at else None,
            'is_locked': self.is_locked
        }


class LeaveBalance(db.Model):
    """Track leave balances per employee per leave type"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    leave_type = db.Column(db.String(50), nullable=False)  # PAID, SICK, UNPAID
    
    # Balance Tracking
    total_days = db.Column(db.Integer, default=0)  # Allocated for the year
    used_days = db.Column(db.Integer, default=0)  # Used/Approved leaves
    available_days = db.Column(db.Integer, default=0)  # Remaining balance
    
    # Audit
    year = db.Column(db.Integer, nullable=False)  # Fiscal year
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'leave_type', 'year', name='uq_user_leave_year'),)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('leave_balances', lazy=True))
    
    def deduct(self, days):
        """Deduct days from balance"""
        if days > self.available_days:
            raise ValueError(f"Insufficient balance. Available: {self.available_days}, Requested: {days}")
        self.used_days += days
        self.available_days -= days
    
    def restore(self, days):
        """Restore days to balance (for rejected/cancelled leaves)"""
        self.used_days = max(0, self.used_days - days)
        self.available_days = self.total_days - self.used_days
    
    @staticmethod
    def initialize_balance(user_id, year=None):
        """Initialize leave balances for a new employee"""
        if year is None:
            year = date.today().year
        
        balances = [
            LeaveBalance(user_id=user_id, leave_type='PAID', total_days=24, available_days=24, year=year),
            LeaveBalance(user_id=user_id, leave_type='SICK', total_days=7, available_days=7, year=year),
            LeaveBalance(user_id=user_id, leave_type='UNPAID', total_days=999, available_days=999, year=year)  # Unlimited
        ]
        
        for balance in balances:
            existing = LeaveBalance.query.filter_by(
                user_id=user_id, 
                leave_type=balance.leave_type, 
                year=year
            ).first()
            if not existing:
                db.session.add(balance)
        
        db.session.commit()
        return balances


class Salary(db.Model):
    """Salary information for employees - Component-based calculation engine"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    
    # Core Wage Model
    monthly_wage = db.Column(db.Float, nullable=False, default=0.0)
    yearly_wage = db.Column(db.Float, nullable=False, default=0.0)
    
    # Working Schedule (Metadata)
    working_days_per_week = db.Column(db.Integer, default=5)
    daily_working_hours = db.Column(db.Float, default=8.0)
    break_time_hours = db.Column(db.Float, default=1.0)
    
    # Salary Components (Auto-calculated)
    basic_salary = db.Column(db.Float, default=0.0)
    hra = db.Column(db.Float, default=0.0)
    standard_allowance = db.Column(db.Float, default=4167.0)  # Fixed component
    performance_bonus = db.Column(db.Float, default=0.0)
    lta = db.Column(db.Float, default=0.0)
    fixed_allowance = db.Column(db.Float, default=0.0)  # Auto-balanced (residual)
    gross_salary = db.Column(db.Float, default=0.0)
    
    # Provident Fund (PF) - Calculated on Basic Salary only
    employee_pf_percent = db.Column(db.Float, default=12.0)
    employer_pf_percent = db.Column(db.Float, default=12.0)
    employee_pf_amount = db.Column(db.Float, default=0.0)
    employer_pf_amount = db.Column(db.Float, default=0.0)
    
    # Tax Deductions
    professional_tax = db.Column(db.Float, default=200.0)  # Fixed monthly
    
    # Net Salary (After all deductions)
    net_salary = db.Column(db.Float, default=0.0)
    
    # Audit
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_locked = db.Column(db.Boolean, default=False)  # Lock if payroll processed
    
    def calculate_breakdown(self):
        """
        Component-based Calculation Engine
        ===================================
        Follows strict validation rules:
        1. All components calculated from wage
        2. Fixed Allowance auto-balances (residual)
        3. Sum of components MUST equal wage
        4. PF calculated only on Basic Salary
        """
        # Ensure all values have defaults (prevent NoneType errors)
        self.monthly_wage = float(self.monthly_wage or 0)
        self.employee_pf_percent = float(self.employee_pf_percent or 12.0)
        self.employer_pf_percent = float(self.employer_pf_percent or 12.0)
        self.professional_tax = float(self.professional_tax or 200.0)
        self.standard_allowance = float(self.standard_allowance or 4167.0)
        
        # Step 1: Derive yearly wage
        self.yearly_wage = self.monthly_wage * 12
        
        # Step 2: Calculate Basic Salary (50% of wage)
        self.basic_salary = self.monthly_wage * 0.5
        
        # Step 3: Calculate HRA (50% of Basic)
        self.hra = self.basic_salary * 0.5
        
        # Step 4: Standard Allowance (Fixed component - now configurable)
        # Keep existing value or use default
        if self.standard_allowance == 0:
            self.standard_allowance = 4167.0
        
        # Step 5: Performance Bonus (8.33% of Basic)
        self.performance_bonus = self.basic_salary * 0.0833
        
        # Step 6: LTA (8.33% of Basic)
        self.lta = self.basic_salary * 0.0833
        
        # Step 7: Calculate Fixed Allowance (AUTO-BALANCED)
        # This ensures total components = wage
        total_without_fixed = (
            self.basic_salary + 
            self.hra + 
            self.standard_allowance + 
            self.performance_bonus + 
            self.lta
        )
        self.fixed_allowance = max(0, self.monthly_wage - total_without_fixed)
        
        # Step 8: Gross Salary = Monthly Wage (always equal)
        self.gross_salary = self.monthly_wage
        
        # Step 9: Calculate PF (on Basic Salary only)
        self.employee_pf_amount = self.basic_salary * (self.employee_pf_percent / 100)
        self.employer_pf_amount = self.basic_salary * (self.employer_pf_percent / 100)
        
        # Step 10: Calculate Net Salary (Gross - Deductions)
        total_deductions = self.employee_pf_amount + self.professional_tax
        self.net_salary = self.gross_salary - total_deductions
        
        # Step 10: Calculate Net Salary (Gross - Deductions)
        total_deductions = self.employee_pf_amount + self.professional_tax
        self.net_salary = self.gross_salary - total_deductions
    
    def validate_components(self):
        """
        Validation Rules (Non-Negotiable)
        ==================================
        1. Sum of all components must equal wage
        2. Components cannot exceed wage
        3. Fixed Allowance is auto-balanced
        """
        total_components = (
            self.basic_salary + 
            self.hra + 
            self.standard_allowance + 
            self.performance_bonus + 
            self.lta + 
            self.fixed_allowance
        )
        
        # Check if sum equals wage (with small tolerance for float precision)
        difference = abs(total_components - self.monthly_wage)
        if difference > 0.01:  # Tolerance of 1 paisa
            raise ValueError(
                f"Component sum ({total_components:.2f}) does not equal wage ({self.monthly_wage:.2f}). "
                f"Difference: {difference:.2f}"
            )
        
        # Check if any component exceeds wage
        if total_components > self.monthly_wage:
            raise ValueError(
                f"Total components ({total_components:.2f}) exceed wage ({self.monthly_wage:.2f})"
            )
        
        return True
    
    def get_component_structure(self):
        """
        Return component structure following universal schema
        ======================================================
        Each component has:
        - name: Component name
        - calculation_type: PERCENTAGE | FIXED
        - base: WAGE | BASIC
        - value: percentage or fixed amount
        - auto_calculated: boolean
        """
        return [
            {
                "name": "Basic Salary",
                "calculation_type": "PERCENTAGE",
                "base": "WAGE",
                "value": 50,
                "calculated_amount": self.basic_salary,
                "auto_calculated": True
            },
            {
                "name": "HRA",
                "calculation_type": "PERCENTAGE",
                "base": "BASIC",
                "value": 50,
                "calculated_amount": self.hra,
                "auto_calculated": True
            },
            {
                "name": "Standard Allowance",
                "calculation_type": "FIXED",
                "base": None,
                "value": self.standard_allowance,
                "calculated_amount": self.standard_allowance,
                "auto_calculated": False
            },
            {
                "name": "Performance Bonus",
                "calculation_type": "PERCENTAGE",
                "base": "BASIC",
                "value": 8.33,
                "calculated_amount": self.performance_bonus,
                "auto_calculated": True
            },
            {
                "name": "LTA",
                "calculation_type": "PERCENTAGE",
                "base": "BASIC",
                "value": 8.33,
                "calculated_amount": self.lta,
                "auto_calculated": True
            },
            {
                "name": "Fixed Allowance",
                "calculation_type": "RESIDUAL",
                "base": "WAGE",
                "value": None,
                "calculated_amount": self.fixed_allowance,
                "auto_calculated": True,
                "note": "Auto-balanced to ensure total = wage"
            }
        ]
    
    def to_dict(self):
        """Enhanced dictionary representation with component structure"""
        return {
            'wage_details': {
                'monthly_wage': round(self.monthly_wage, 2),
                'yearly_wage': round(self.yearly_wage, 2),
                'working_days_per_week': self.working_days_per_week,
                'daily_working_hours': self.daily_working_hours,
                'break_time_hours': self.break_time_hours
            },
            'breakdown': {
                'basic': round(self.basic_salary, 2),
                'hra': round(self.hra, 2),
                'standard_allowance': round(self.standard_allowance, 2),
                'performance_bonus': round(self.performance_bonus, 2),
                'lta': round(self.lta, 2),
                'fixed_allowance': round(self.fixed_allowance, 2),
                'gross_salary': round(self.gross_salary, 2)
            },
            'pf': {
                'employee_percent': self.employee_pf_percent,
                'employer_percent': self.employer_pf_percent,
                'employee_amount': round(self.employee_pf_amount, 2),
                'employer_amount': round(self.employer_pf_amount, 2)
            },
            'tax': {
                'professional_tax': round(self.professional_tax, 2)
            },
            'net_salary': round(self.net_salary, 2),
            'components': self.get_component_structure(),
            'is_locked': self.is_locked
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
    
    # Schema migration: Add is_locked column to salary table if it doesn't exist
    try:
        with db.engine.connect() as conn:
            result = conn.execute(text("PRAGMA table_info(salary)"))
            columns = [row[1] for row in result.fetchall()]
            
            if 'is_locked' not in columns:
                conn.execute(text("ALTER TABLE salary ADD COLUMN is_locked BOOLEAN DEFAULT 0"))
                conn.commit()
                print("✅ Added 'is_locked' column to salary table")
    except Exception as e:
        print(f"⚠️ Schema migration note (salary): {e}")
    
    # Schema migration: Add break_minutes, work_hours, extra_hours to attendance table
    try:
        with db.engine.connect() as conn:
            result = conn.execute(text("PRAGMA table_info(attendance)"))
            columns = [row[1] for row in result.fetchall()]
            
            if 'break_minutes' not in columns:
                conn.execute(text("ALTER TABLE attendance ADD COLUMN break_minutes INTEGER DEFAULT 60"))
                conn.commit()
                print("✅ Added 'break_minutes' column to attendance table")
            
            if 'work_hours' not in columns:
                conn.execute(text("ALTER TABLE attendance ADD COLUMN work_hours REAL DEFAULT 0.0"))
                conn.commit()
                print("✅ Added 'work_hours' column to attendance table")
            
            if 'extra_hours' not in columns:
                conn.execute(text("ALTER TABLE attendance ADD COLUMN extra_hours REAL DEFAULT 0.0"))
                conn.commit()
                print("✅ Added 'extra_hours' column to attendance table")
    except Exception as e:
        print(f"⚠️ Schema migration note (attendance): {e}")
    
    # Schema migration: Add new columns to leave table for enhanced functionality
    try:
        with db.engine.connect() as conn:
            result = conn.execute(text("PRAGMA table_info(leave)"))
            columns = [row[1] for row in result.fetchall()]
            
            if 'is_paid' not in columns:
                conn.execute(text("ALTER TABLE leave ADD COLUMN is_paid BOOLEAN DEFAULT 1"))
                conn.commit()
                print("✅ Added 'is_paid' column to leave table")
            
            if 'attachment_file' not in columns:
                conn.execute(text("ALTER TABLE leave ADD COLUMN attachment_file TEXT"))
                conn.commit()
                print("✅ Added 'attachment_file' column to leave table")
            
            if 'reviewed_by' not in columns:
                conn.execute(text("ALTER TABLE leave ADD COLUMN reviewed_by INTEGER"))
                conn.commit()
                print("✅ Added 'reviewed_by' column to leave table")
            
            if 'reviewed_at' not in columns:
                conn.execute(text("ALTER TABLE leave ADD COLUMN reviewed_at DATETIME"))
                conn.commit()
                print("✅ Added 'reviewed_at' column to leave table")
            
            if 'updated_at' not in columns:
                conn.execute(text("ALTER TABLE leave ADD COLUMN updated_at DATETIME"))
                conn.commit()
                print("✅ Added 'updated_at' column to leave table")
            
            if 'is_locked' not in columns:
                conn.execute(text("ALTER TABLE leave ADD COLUMN is_locked BOOLEAN DEFAULT 0"))
                conn.commit()
                print("✅ Added 'is_locked' column to leave table")
    except Exception as e:
        print(f"⚠️ Schema migration note (leave): {e}")
    
    # Delete demo users if they exist
    demo_users = User.query.filter(User.username.in_(['demo'])).all()
    for demo in demo_users:
        db.session.delete(demo)
        print(f"🗑️ Deleted demo user: {demo.username}")
    db.session.commit()
    
    # Create default admin if doesn't exist
    admin_user = User.query.filter_by(role='Admin').first()
    if not admin_user:
        # Generate OTP for admin
        admin_otp = generate_otp()
        
        admin_user = User(
            fullname='Jay Raychura',
            username='admin',
            login_id='JARA20260001',  # Jay Raychura 2026 0001
            email='jayraychura13@gmail.com',
            role='Admin',
            year_of_joining=2026,
            is_first_login=True,  # Admin needs to verify email and set password
            email_verified=False,  # Requires email verification
            registration_approved=True,  # Admin is auto-approved
            newsletter=False
        )
        admin_user.set_password('Admin@123')  # Temporary password
        admin_user.set_otp(admin_otp)
        
        db.session.add(admin_user)
        db.session.commit()
        
        # Send OTP email to admin
        send_otp_email(admin_user.email, admin_user.fullname, admin_user.login_id, admin_otp)
        print("✅ Admin created: login_id=JARA20260001, email=jayraychura13@gmail.com")
        print("📧 Verification email sent to admin")
    
    # Create default company if doesn't exist
    default_company = Company.query.filter_by(company_code='DF').first()
    if not default_company:
        default_company = Company(
            name='Dayflow',
            company_code='DF',
            description='Dayflow HRMS - Default Company',
            industry='Technology',
            is_active=True
        )
        db.session.add(default_company)
        db.session.commit()
        print("✅ Default company created: Dayflow (DF)")


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
            # Check if registration is approved (for employees)
            if user.role == 'Employee' and not user.registration_approved:
                flash('Your registration is pending HR approval. Please wait for confirmation.', 'warning')
                return redirect(url_for('login'))
            
            # Check if email is verified
            if not user.email_verified:
                # Store user_id in session for OTP verification
                session['user_id'] = user.id
                session['user'] = user.username
                session['email_verified'] = False
                flash('Please verify your email address before logging in. Check your inbox for verification instructions.', 'warning')
                return redirect(url_for('verify_otp'))
            
            session['user_id'] = user.id
            session['user'] = user.username
            session['role'] = user.role
            session['is_first_login'] = user.is_first_login
            session['email_verified'] = user.email_verified
            
            # Update last login info
            user.last_login_at = datetime.now()
            db.session.commit()
            
            # Check if first login - requires password setup
            if user.is_first_login:
                flash('Welcome! Please change your password for security.', 'warning')
                return redirect(url_for('change_password'))
            
            flash('Login successful!', 'success')
            
            # All users redirect to employees directory after login
            return redirect(url_for('employees'))
        else:
            flash('Invalid credentials. Please try again.', 'error')
    
    return render_template('login.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot password page - sends reset link to user's email"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        if not email:
            flash('Please enter your email address.', 'error')
            return render_template('forgot_password.html')
        
        # Find user by email
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate reset token
            reset_token = generate_reset_token()
            user.reset_token = reset_token
            user.reset_token_expiry = datetime.now() + timedelta(hours=1)
            
            try:
                db.session.commit()
                
                # Send password reset email
                if send_password_reset_email(user.email, user.fullname, reset_token):
                    flash('Password reset link has been sent to your email address. Please check your inbox.', 'success')
                else:
                    flash('Failed to send reset email. Please try again or contact support.', 'error')
            except Exception as e:
                db.session.rollback()
                print(f"Error saving reset token: {str(e)}")
                flash('An error occurred. Please try again later.', 'error')
        else:
            # Don't reveal if email exists or not for security
            flash('If an account with that email exists, a password reset link has been sent.', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password using token from email"""
    # Find user with this token
    user = User.query.filter_by(reset_token=token).first()
    
    # Validate token
    if not user or not user.reset_token_expiry:
        flash('Invalid or expired password reset link.', 'error')
        return redirect(url_for('login'))
    
    # Check if token is expired
    if datetime.now() > user.reset_token_expiry:
        flash('Password reset link has expired. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate passwords match
        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)
        
        # Validate password strength
        is_valid, error_msg = validate_password(new_password)
        if not is_valid:
            flash(error_msg, 'error')
            return render_template('reset_password.html', token=token)
        
        try:
            # Update password
            user.set_password(new_password)
            user.password_updated_at = datetime.now()
            
            # Clear reset token
            user.reset_token = None
            user.reset_token_expiry = None
            
            # If this was first login, mark it as done
            if user.is_first_login:
                user.is_first_login = False
            
            db.session.commit()
            
            flash('Your password has been reset successfully. Please log in with your new password.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            print(f"Error resetting password: {str(e)}")
            flash('An error occurred. Please try again.', 'error')
            return render_template('reset_password.html', token=token)
    
    return render_template('reset_password.html', token=token, user=user)


@app.route('/register', methods=['GET', 'POST'])
def employee_register():
    """Public employee registration page - requires company selection and HR approval"""
    if request.method == 'POST':
        fullname = request.form.get('fullname', '').strip()
        email = request.form.get('email', '').strip()
        company_id = request.form.get('company_id', '').strip()
        department = request.form.get('department', '').strip()
        designation = request.form.get('designation', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not all([fullname, email, company_id, password, confirm_password]):
            flash('Please fill in all required fields.', 'error')
        elif password != confirm_password:
            flash('Passwords do not match.', 'error')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered. Please use another email or login.', 'error')
        else:
            # Validate password strength
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                flash(error_msg, 'error')
            else:
                try:
                    company = Company.query.get(int(company_id))
                    if not company or not company.is_active:
                        flash('Invalid company selected.', 'error')
                        return render_template('employee_register.html', companies=Company.query.filter_by(is_active=True).all())
                    
                    year_of_joining = datetime.now().year
                    
                    # Generate login credentials
                    login_id = generate_login_id(fullname, year_of_joining, company.company_code)
                    username = login_id
                    
                    # Generate OTP for email verification
                    otp = generate_otp()
                    
                    # Create new employee (pending approval)
                    user = User(
                        fullname=fullname,
                        username=username,
                        login_id=login_id,
                        email=email,
                        role='Employee',
                        company=company.name,
                        company_id=company.id,
                        year_of_joining=year_of_joining,
                        department=department,
                        designation=designation,
                        is_first_login=True,
                        email_verified=False,
                        registration_approved=False,  # Requires HR approval
                        newsletter=False
                    )
                    user.set_password(password)
                    user.set_otp(otp)
                    
                    db.session.add(user)
                    db.session.commit()
                    
                    # Send OTP email
                    if send_otp_email(user.email, user.fullname, user.login_id, otp):
                        flash(f'Registration successful! Your Login ID is {login_id}. Please check your email to verify your account. Note: Your account requires HR approval before you can access the system.', 'success')
                        return redirect(url_for('login'))
                    else:
                        flash('Registration successful but failed to send verification email. Please contact support.', 'warning')
                        return redirect(url_for('login'))
                        
                except Exception as e:
                    db.session.rollback()
                    print(f"Registration error: {str(e)}")
                    flash('An error occurred during registration. Please try again.', 'error')
    
    # Get active companies for selection
    companies = Company.query.filter_by(is_active=True).all()
    return render_template('employee_register.html', companies=companies)


@app.route('/signup', methods=['GET', 'POST'])
@role_required('Admin')
def signup():
    """Admin-only signup page - Create HR Officers and Companies"""
    if request.method == 'POST':
        action = request.form.get('action', 'create_hr')
        
        if action == 'create_company':
            # Create new company
            company_name = request.form.get('company_name', '').strip()
            company_code = request.form.get('company_code', '').strip().upper()
            description = request.form.get('description', '').strip()
            industry = request.form.get('industry', '').strip()
            
            if not all([company_name, company_code]):
                flash('Please provide company name and code.', 'error')
            elif Company.query.filter_by(company_code=company_code).first():
                flash('Company code already exists.', 'error')
            elif Company.query.filter_by(name=company_name).first():
                flash('Company name already exists.', 'error')
            else:
                try:
                    company = Company(
                        name=company_name,
                        company_code=company_code,
                        description=description,
                        industry=industry,
                        created_by=session['user_id'],
                        is_active=True
                    )
                    db.session.add(company)
                    db.session.commit()
                    flash(f'Company "{company_name}" created successfully!', 'success')
                except Exception as e:
                    db.session.rollback()
                    flash('Error creating company. Please try again.', 'error')
                    print(f"Error: {e}")
        
        elif action == 'create_hr':
            # Create HR Officer
            fullname = request.form.get('fullname', '').strip()
            email = request.form.get('email', '').strip()
            company_id = request.form.get('company_id', '').strip()
            department = request.form.get('department', '').strip()
            year_of_joining = int(request.form.get('year_of_joining', datetime.now().year))
            
            if not all([fullname, email, company_id]):
                flash('Please fill in all required fields.', 'error')
            elif User.query.filter_by(email=email).first():
                flash('Email already registered.', 'error')
            else:
                try:
                    company = Company.query.get(int(company_id))
                    if not company:
                        flash('Invalid company selected.', 'error')
                    else:
                        # Generate credentials
                        login_id = generate_login_id(fullname, year_of_joining, company.company_code)
                        temp_password = generate_temp_password()
                        
                        # Validate password
                        is_valid, error_msg = validate_password(temp_password)
                        while not is_valid:
                            temp_password = generate_temp_password()
                            is_valid, error_msg = validate_password(temp_password)
                        
                        # Generate OTP
                        otp = generate_otp()
                        
                        # Create HR Officer
                        user = User(
                            fullname=fullname,
                            username=login_id,
                            login_id=login_id,
                            email=email,
                            company=company.name,
                            company_id=company.id,
                            department=department,
                            role='HR Officer',
                            year_of_joining=year_of_joining,
                            is_first_login=True,
                            email_verified=False,
                            registration_approved=True,  # Admin-created users are auto-approved
                            newsletter=False
                        )
                        user.set_password(temp_password)
                        user.set_otp(otp)
                        
                        db.session.add(user)
                        db.session.commit()
                        
                        # Send OTP email
                        send_otp_email(user.email, user.fullname, user.login_id, otp)
                        
                        flash(f'HR Officer created! Login ID: {login_id}, Temp Password: {temp_password}', 'success')
                        
                except Exception as e:
                    db.session.rollback()
                    flash('Error creating HR Officer. Please try again.', 'error')
                    print(f"Error: {e}")
    
    # Get all companies for dropdown
    companies = Company.query.filter_by(is_active=True).all()
    return render_template('signup.html', companies=companies)


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
    
    # Get attendance stats for this user
    total_attendance = Attendance.query.filter_by(user_id=user.id).count()
    attendance_this_month = Attendance.query.filter(
        Attendance.user_id == user.id,
        db.extract('month', Attendance.date) == datetime.now().month,
        db.extract('year', Attendance.date) == datetime.now().year
    ).count()
    
    # Get leave stats
    total_leaves = Leave.query.filter_by(user_id=user.id).count()
    pending_leaves = Leave.query.filter_by(user_id=user.id, status='Pending').count()
    approved_leaves = Leave.query.filter_by(user_id=user.id, status='Approved').count()
    
    # Get today's attendance
    today_attendance = Attendance.query.filter_by(
        user_id=user.id,
        date=date.today()
    ).first()
    
    # Calculate work hours this month
    monthly_attendance = Attendance.query.filter(
        Attendance.user_id == user.id,
        db.extract('month', Attendance.date) == datetime.now().month,
        db.extract('year', Attendance.date) == datetime.now().year
    ).all()
    total_work_hours = sum([att.work_hours or 0 for att in monthly_attendance])
    
    # Get recent activities (last 5 attendance records or leave requests)
    recent_attendance = Attendance.query.filter_by(user_id=user.id).order_by(Attendance.date.desc()).limit(3).all()
    recent_leaves = Leave.query.filter_by(user_id=user.id).order_by(Leave.applied_on.desc()).limit(2).all()
    
    user_data = {
        'fullname': user.fullname,
        'username': user.username,
        'login_id': user.login_id or user.username,
        'email': user.email,
        'role': user.role,
        'joined': user.created_at.strftime('%B %Y'),
        'newsletter': user.newsletter,
        'total_users': total_users,
        'total_attendance': total_attendance,
        'attendance_this_month': attendance_this_month,
        'total_leaves': total_leaves,
        'pending_leaves': pending_leaves,
        'approved_leaves': approved_leaves,
        'today_attendance': today_attendance,
        'total_work_hours': round(total_work_hours, 2),
        'recent_attendance': recent_attendance,
        'recent_leaves': recent_leaves
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
    
    # Get pending employee registrations for this company
    if user.role == 'HR Officer':
        pending_registrations = User.query.filter_by(
            role='Employee',
            registration_approved=False,
            company_id=user.company_id
        ).all()
    else:  # Admin sees all
        pending_registrations = User.query.filter_by(
            role='Employee',
            registration_approved=False
        ).all()
    
    # HR stats
    total_employees = User.query.filter_by(role='Employee', registration_approved=True).count()
    total_attendance_today = Attendance.query.filter_by(date=date.today()).count()
    pending_leaves = Leave.query.filter_by(status='Pending').count()
    
    hr_data = {
        'fullname': user.fullname,
        'login_id': user.login_id,
        'total_employees': total_employees,
        'total_attendance_today': total_attendance_today,
        'pending_leaves': pending_leaves,
        'pending_registrations': pending_registrations,
        'pending_count': len(pending_registrations)
    }
    
    return render_template('hr_dashboard.html', user=session['user'], hr_data=hr_data)


@app.route('/hr/approve-employee/<int:user_id>', methods=['POST'])
@role_required('HR Officer', 'Admin')
def approve_employee(user_id):
    """Approve employee registration"""
    hr_user = User.query.get(session['user_id'])
    employee = User.query.get(user_id)
    
    if not employee or employee.role != 'Employee':
        flash('Employee not found.', 'error')
        return redirect(url_for('hr_dashboard'))
    
    # HR Officer can only approve employees from their company
    if hr_user.role == 'HR Officer' and employee.company_id != hr_user.company_id:
        flash('You can only approve employees from your company.', 'error')
        return redirect(url_for('hr_dashboard'))
    
    employee.registration_approved = True
    employee.approved_by = session['user_id']
    employee.approved_at = datetime.now()
    db.session.commit()
    
    flash(f'Employee {employee.fullname} approved successfully!', 'success')
    return redirect(url_for('hr_dashboard'))


@app.route('/hr/reject-employee/<int:user_id>', methods=['POST'])
@role_required('HR Officer', 'Admin')
def reject_employee(user_id):
    """Reject and delete employee registration"""
    hr_user = User.query.get(session['user_id'])
    employee = User.query.get(user_id)
    
    if not employee or employee.role != 'Employee':
        flash('Employee not found.', 'error')
        return redirect(url_for('hr_dashboard'))
    
    # HR Officer can only reject employees from their company
    if hr_user.role == 'HR Officer' and employee.company_id != hr_user.company_id:
        flash('You can only reject employees from your company.', 'error')
        return redirect(url_for('hr_dashboard'))
    
    employee_name = employee.fullname
    db.session.delete(employee)
    db.session.commit()
    
    flash(f'Employee {employee_name} registration rejected and removed.', 'success')
    return redirect(url_for('hr_dashboard'))


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
            
            # Redirect to employees page
            return redirect(url_for('employees'))
    
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
            # Already verified and password set, go to employees page
            return redirect(url_for('employees'))
    
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
            
            # Update session with verification status
            session['email_verified'] = True
            session['needs_password_change'] = user.is_first_login
            
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
    
    # If password already set (not first login), redirect to employees page
    if not user.is_first_login:
        return redirect(url_for('employees'))
    
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
            
            # Redirect to employees page
            return redirect(url_for('employees'))
    
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
    
    # Get search query
    search_query = request.args.get('search', '').strip()
    
    # Get all employees with optional search filtering
    if search_query:
        all_employees = User.query.filter(
            db.or_(
                User.fullname.ilike(f'%{search_query}%'),
                User.login_id.ilike(f'%{search_query}%'),
                User.email.ilike(f'%{search_query}%'),
                User.department.ilike(f'%{search_query}%') if hasattr(User, 'department') else False
            )
        ).all()
    else:
        all_employees = User.query.all()
    
    # Calculate stats
    stats = {
        'present': 0,
        'on_leave': 0,
        'absent': 0,
        'in_progress': 0
    }
    
    # Build employee data with status
    employees_data = []
    for emp in all_employees:
        status = get_employee_status(emp.id)
        
        # Determine if checked in but not checked out
        today_attendance = get_today_attendance(emp.id)
        if status == 'present' and today_attendance and today_attendance.check_in and not today_attendance.check_out:
            status = 'in_progress'
        
        # Update stats
        if status == 'present':
            stats['present'] += 1
        elif status == 'on_leave':
            stats['on_leave'] += 1
        elif status == 'in_progress':
            stats['in_progress'] += 1
        else:
            stats['absent'] += 1
        
        # Get photo URL if available
        photo_url = None
        if hasattr(emp, 'profile_pic') and emp.profile_pic:
            photo_url = url_for('static', filename=f'uploads/{emp.profile_pic}')
        
        employees_data.append({
            'id': emp.id,
            'fullname': emp.fullname,
            'login_id': emp.login_id,
            'email': emp.email,
            'role': emp.role,
            'designation': emp.designation if hasattr(emp, 'designation') else None,
            'department': emp.department if hasattr(emp, 'department') else None,
            'status': status,
            'photo_url': photo_url,
            'check_in_time': today_attendance.check_in.strftime('%I:%M %p') if today_attendance and today_attendance.check_in else None,
            'is_current_user': emp.id == current_user.id
        })
    
    return render_template('employees.html',
                         user=session['user'],
                         current_user=current_user,
                         employees_data=employees_data,
                         search_query=search_query,
                         stats=stats)


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
    """Attendance entry point - redirect based on role"""
    user = User.query.get(session['user_id'])
    
    if not user:
        session.clear()
        flash('Please login again.', 'error')
        return redirect(url_for('login'))
    
    # Role-based routing
    if user.role in ['Admin', 'HR Officer']:
        return redirect(url_for('attendance_all'))
    else:
        return redirect(url_for('attendance_me'))


@app.route('/attendance/me')
@login_required
def attendance_me():
    """Employee Monthly Attendance View - Self Only"""
    user = User.query.get(session['user_id'])
    
    if not user:
        session.clear()
        flash('Please login again.', 'error')
        return redirect(url_for('login'))
    
    # Get month parameter or default to current month
    view_month = request.args.get('month')
    if view_month:
        try:
            target_month = datetime.strptime(view_month, '%Y-%m').date()
        except ValueError:
            target_month = date.today().replace(day=1)
    else:
        target_month = date.today().replace(day=1)
    
    # Calculate month boundaries
    if target_month.month == 12:
        next_month = target_month.replace(year=target_month.year + 1, month=1)
    else:
        next_month = target_month.replace(month=target_month.month + 1)
    
    if target_month.month == 1:
        prev_month = target_month.replace(year=target_month.year - 1, month=12)
    else:
        prev_month = target_month.replace(month=target_month.month - 1)
    
    # Fetch attendance records for the month
    records = Attendance.query.filter(
        Attendance.user_id == user.id,
        Attendance.date >= target_month,
        Attendance.date < next_month
    ).order_by(Attendance.date).all()
    
    # Build record dictionary for quick lookup
    record_dict = {r.date: r for r in records}
    
    # Fetch approved leaves for the month
    leaves = Leave.query.filter(
        Leave.user_id == user.id,
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
    
    # Build attendance data for each day
    attendance_data = []
    days_present = 0
    total_working_days = 0
    leaves_count = len(leave_dates)
    
    current = target_month
    while current < next_month:
        total_working_days += 1
        
        record = record_dict.get(current)
        is_leave = current in leave_dates
        
        if is_leave:
            # Priority 1: Leave
            attendance_data.append({
                'date': current.strftime('%d %b, %Y'),
                'check_in': 'On Leave',
                'check_out': '—',
                'work_hours': '—',
                'extra_hours': '—',
                'status': 'Leave',
                'status_class': 'leave'
            })
            days_present += 1  # Leave counts as present day
        elif record and record.check_in:
            # Priority 2: Checked in
            check_in_display = record.check_in.strftime('%I:%M %p')
            
            if record.check_out:
                check_out_display = record.check_out.strftime('%I:%M %p')
                work_hours_display = f'{int(record.work_hours)}h {int((record.work_hours % 1) * 60)}m'
                extra_hours_display = f'{int(record.extra_hours)}h {int((record.extra_hours % 1) * 60)}m' if record.extra_hours > 0 else '0h'
                status = 'Present'
                status_class = 'present'
                days_present += 1
            else:
                check_out_display = '—'
                work_hours_display = '—'
                extra_hours_display = '—'
                status = 'In Progress'
                status_class = 'in-progress'
            
            attendance_data.append({
                'date': current.strftime('%d %b, %Y'),
                'check_in': check_in_display,
                'check_out': check_out_display,
                'work_hours': work_hours_display,
                'extra_hours': extra_hours_display,
                'status': status,
                'status_class': status_class
            })
        else:
            # Priority 3: Absent
            attendance_data.append({
                'date': current.strftime('%d %b, %Y'),
                'check_in': '—',
                'check_out': '—',
                'work_hours': '—',
                'extra_hours': '—',
                'status': 'Absent',
                'status_class': 'absent'
            })
        
        current += timedelta(days=1)
    
    # Calculate payable days for payroll reference
    absent_days = total_working_days - days_present
    payable_days = total_working_days - absent_days
    
    return render_template('attendance_me.html',
                         user=user,
                         target_month=target_month,
                         attendance_data=attendance_data,
                         days_present=days_present,
                         leaves_count=leaves_count,
                         total_working_days=total_working_days,
                         payable_days=payable_days,
                         prev_month=prev_month.strftime('%Y-%m'),
                         next_month=next_month.strftime('%Y-%m'),
                         current_month=target_month.strftime('%B %Y'))


@app.route('/api/attendance/today')
@login_required
def api_attendance_today():
    """API: Get today's attendance status for current user"""
    try:
        user_id = session['user_id']
        today = date.today()
        
        # Get today's attendance record
        attendance = Attendance.query.filter_by(
            user_id=user_id,
            date=today
        ).first()
        
        if attendance:
            return jsonify({
                'success': True,
                'attendance': {
                    'check_in': attendance.check_in.isoformat() if attendance.check_in else None,
                    'check_out': attendance.check_out.isoformat() if attendance.check_out else None,
                    'work_hours': attendance.work_hours,
                    'extra_hours': attendance.extra_hours
                }
            })
        else:
            return jsonify({
                'success': True,
                'attendance': {
                    'check_in': None,
                    'check_out': None,
                    'work_hours': 0,
                    'extra_hours': 0
                }
            })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/attendance/checkin', methods=['POST'])
@login_required
def api_attendance_checkin():
    """API: Check in for today"""
    try:
        user_id = session['user_id']
        today = date.today()
        now = datetime.now()
        
        # Check if already checked in today
        attendance = Attendance.query.filter_by(
            user_id=user_id,
            date=today
        ).first()
        
        if attendance and attendance.check_in:
            return jsonify({
                'success': False,
                'message': 'You have already checked in today.'
            }), 400
        
        # Create or update attendance record
        if not attendance:
            attendance = Attendance(
                user_id=user_id,
                date=today,
                check_in=now
            )
            db.session.add(attendance)
        else:
            attendance.check_in = now
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Checked in successfully!',
            'check_in': now.isoformat()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/attendance/checkout', methods=['POST'])
@login_required
def api_attendance_checkout():
    """API: Check out for today"""
    try:
        user_id = session['user_id']
        today = date.today()
        now = datetime.now()
        
        # Get today's attendance record
        attendance = Attendance.query.filter_by(
            user_id=user_id,
            date=today
        ).first()
        
        if not attendance or not attendance.check_in:
            return jsonify({
                'success': False,
                'message': 'You need to check in first.'
            }), 400
        
        if attendance.check_out:
            return jsonify({
                'success': False,
                'message': 'You have already checked out today.'
            }), 400
        
        # Update checkout time
        attendance.check_out = now
        
        # Calculate work hours (total time - 1 hour break)
        total_minutes = int((now - attendance.check_in).total_seconds() // 60)
        work_minutes = max(0, total_minutes - 60)  # Subtract 1 hour break
        attendance.work_hours = round(work_minutes / 60, 2)
        
        # Calculate extra hours (beyond 8 hours standard)
        standard_hours = 8
        attendance.extra_hours = max(0, round(attendance.work_hours - standard_hours, 2))
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Checked out successfully!',
            'check_out': now.isoformat(),
            'work_hours': attendance.work_hours,
            'extra_hours': attendance.extra_hours
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/attendance/all')
@role_required('Admin', 'HR Officer')
def attendance_all():
    """Admin/HR Attendance Monitoring View - All Employees Daily"""
    user = User.query.get(session['user_id'])
    
    if not user:
        session.clear()
        flash('Please login again.', 'error')
        return redirect(url_for('login'))
    
    # Get date parameter or default to today
    view_date = request.args.get('date')
    search_query = request.args.get('search', '').strip()
    
    if view_date:
        try:
            target_date = datetime.strptime(view_date, '%Y-%m-%d').date()
        except ValueError:
            target_date = date.today()
    else:
        target_date = date.today()
    
    # Get all employees with optional search
    if search_query:
        employees = User.query.filter(
            db.or_(
                User.fullname.ilike(f'%{search_query}%'),
                User.login_id.ilike(f'%{search_query}%'),
                User.email.ilike(f'%{search_query}%')
            )
        ).all()
    else:
        employees = User.query.all()
    
    # Build attendance data for each employee
    attendance_data = []
    stats = {
        'present': 0,
        'on_leave': 0,
        'absent': 0,
        'in_progress': 0
    }
    
    for emp in employees:
        # Get attendance record for the day
        record = Attendance.query.filter_by(user_id=emp.id, date=target_date).first()
        
        # Check for approved leave
        on_leave = Leave.query.filter(
            Leave.user_id == emp.id,
            Leave.status == 'Approved',
            Leave.start_date <= target_date,
            Leave.end_date >= target_date
        ).first()
        
        check_in_display = '—'
        check_out_display = '—'
        work_hours_display = '—'
        extra_hours_display = '—'
        status = 'Absent'
        status_class = 'absent'
        
        if on_leave:
            # Priority 1: Leave
            check_in_display = 'On Leave'
            status = 'Leave'
            status_class = 'leave'
            stats['on_leave'] += 1
        elif record and record.check_in:
            # Priority 2: Checked in
            check_in_display = record.check_in.strftime('%I:%M %p')
            
            if record.check_out:
                check_out_display = record.check_out.strftime('%I:%M %p')
                work_hours_display = f'{int(record.work_hours)}h {int((record.work_hours % 1) * 60)}m'
                extra_hours_display = f'{int(record.extra_hours)}h {int((record.extra_hours % 1) * 60)}m' if record.extra_hours > 0 else '0h'
                status = 'Present'
                status_class = 'present'
                stats['present'] += 1
            else:
                status = 'In Progress'
                status_class = 'in-progress'
                stats['in_progress'] += 1
        else:
            # Priority 3: Absent
            stats['absent'] += 1
        
        attendance_data.append({
            'employee_id': emp.id,
            'employee_name': emp.fullname,
            'login_id': emp.login_id,
            'check_in': check_in_display,
            'check_out': check_out_display,
            'work_hours': work_hours_display,
            'extra_hours': extra_hours_display,
            'status': status,
            'status_class': status_class
        })
    
    return render_template('attendance_all.html',
                         user=user,
                         target_date=target_date,
                         attendance_data=attendance_data,
                         stats=stats,
                         search_query=search_query,
                         prev_date=(target_date - timedelta(days=1)).strftime('%Y-%m-%d'),
                         next_date=(target_date + timedelta(days=1)).strftime('%Y-%m-%d'),
                         current_date=target_date.strftime('%d %B %Y'))


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
    
    # Check if view-only mode is requested
    view_mode = request.args.get('mode', '').lower()
    is_view_only = (view_mode == 'view')
    
    # Determine which user profile to show
    if user_id is None:
        # Viewing own profile
        user = viewer
        is_self_view = True
        editable = not is_view_only  # Respect view-only mode even for self
    else:
        # Viewing another user's profile
        user = User.query.get(user_id)
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('employees'))
        is_self_view = (user.id == viewer.id)
        
        # Permission rules:
        # - Employees viewing others: always view-only
        # - Admin/HR viewing others: can edit unless mode=view
        if viewer.role == 'Employee' and not is_self_view:
            editable = False
        else:
            editable = (is_self_view or viewer.role in ['Admin', 'HR Officer']) and not is_view_only
    
    # Determine if viewer is HR/Admin
    is_hr_admin_viewer = viewer.role in ['Admin', 'HR Officer']
    
    # Determine dashboard URL based on viewer role
    if viewer.role == 'Admin':
        dashboard_url = url_for('admin_dashboard')
    elif viewer.role == 'HR Officer':
        dashboard_url = url_for('hr_dashboard')
    else:
        dashboard_url = url_for('dashboard')
    
    # Get salary data - ADMIN and HR can view/edit salary, employees can view their own
    salary_data = None
    can_manage_salary = viewer.role in ['Admin', 'HR Officer']
    can_view_salary = can_manage_salary or is_self_view
    
    if user.role == 'Employee' and can_view_salary:
        salary_data = get_salary_data(user.id)
    
    return render_template('profile.html', 
                         user=user, 
                         viewer=viewer,
                         editable=editable,
                         is_view_only=is_view_only,
                         is_self_view=is_self_view,
                         is_hr_admin_viewer=is_hr_admin_viewer,
                         can_manage_salary=can_manage_salary,
                         can_view_salary=can_view_salary,
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
    
    # Check if salary is configured (for HR/Admin)
    has_salary = False
    if current_user.role in ['Admin', 'HR Officer'] and employee.role == 'Employee':
        salary = Salary.query.filter_by(user_id=employee.id).first()
        has_salary = salary is not None
    
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
        'check_out_time': today_attendance.check_out.strftime('%I:%M %p') if today_attendance and today_attendance.check_out else None,
        'has_salary': has_salary
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


# ============= TIME-OFF MODULE ROUTES (Enhanced Leave System) =============

@app.route('/time-off')
@login_required
def time_off_redirect():
    """Smart redirect based on user role"""
    current_user = User.query.get(session['user_id'])
    if not current_user:
        return redirect(url_for('login'))
    
    # Admin and HR Officer → Management view
    if current_user.role in ['Admin', 'HR Officer']:
        return redirect(url_for('time_off_all'))
    
    # Employees → Personal view
    return redirect(url_for('time_off_me'))


@app.route('/time-off/me')
@login_required
def time_off_me():
    """Employee time-off view - Personal leave requests and balances"""
    current_user = User.query.get(session['user_id'])
    if not current_user:
        return redirect(url_for('login'))
    
    # Get current year for balance calculation
    current_year = datetime.now().year
    
    # Initialize leave balances if they don't exist
    LeaveBalance.initialize_balance(current_user.id, current_year)
    
    # Get leave balances for current year
    balances = LeaveBalance.query.filter_by(
        user_id=current_user.id,
        year=current_year
    ).all()
    
    # Convert to dictionary for easy access
    balance_dict = {
        'PAID': {'total': 0, 'used': 0, 'available': 0},
        'SICK': {'total': 0, 'used': 0, 'available': 0},
        'UNPAID': {'total': 0, 'used': 0, 'available': 0}
    }
    
    for balance in balances:
        balance_dict[balance.leave_type] = {
            'total': balance.total_days,
            'used': balance.used_days,
            'available': balance.available_days
        }
    
    # Get all leave requests for the user (most recent first)
    leaves = Leave.query.filter_by(user_id=current_user.id).order_by(Leave.applied_on.desc()).all()
    
    # Calculate statistics for current year
    year_start = datetime(current_year, 1, 1).date()
    today = datetime.now().date()
    
    # Count by status
    pending_count = sum(1 for l in leaves if l.status == 'PENDING')
    approved_count = sum(1 for l in leaves if l.status == 'APPROVED' and l.start_date >= year_start)
    rejected_count = sum(1 for l in leaves if l.status == 'REJECTED' and l.start_date >= year_start)
    
    # Days used this year (approved only)
    days_used_this_year = sum(l.total_days for l in leaves if l.status == 'APPROVED' and l.start_date >= year_start)
    
    # Upcoming leaves (approved, future dates)
    upcoming_leaves = [l for l in leaves if l.status == 'APPROVED' and l.start_date > today]
    
    stats = {
        'pending': pending_count,
        'approved': approved_count,
        'rejected': rejected_count,
        'days_used': days_used_this_year,
        'upcoming': len(upcoming_leaves)
    }
    
    return render_template('time_off_me.html', 
                         user=current_user, 
                         balances=balance_dict,
                         leaves=leaves,
                         stats=stats,
                         current_year=current_year,
                         today=today)


@app.route('/time-off/all')
@login_required
def time_off_all():
    """Admin/HR time-off view - All employee leave requests with approval controls"""
    current_user = User.query.get(session['user_id'])
    if not current_user:
        return redirect(url_for('login'))
    
    # Only Admin and HR Officer can access
    if current_user.role not in ['Admin', 'HR Officer']:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('time_off_me'))
    
    # Get filter parameters
    status_filter = request.args.get('status', 'all')  # all, PENDING, APPROVED, REJECTED
    employee_filter = request.args.get('employee', '')  # employee name or ID
    leave_type_filter = request.args.get('type', 'all')  # all, PAID, SICK, UNPAID
    
    # Base query with user join
    query = db.session.query(Leave, User).join(User, Leave.user_id == User.id)
    
    # Apply filters
    if status_filter != 'all':
        query = query.filter(Leave.status == status_filter)
    
    if employee_filter:
        query = query.filter(
            db.or_(
                User.username.like(f'%{employee_filter}%'),
                User.email.like(f'%{employee_filter}%')
            )
        )
    
    if leave_type_filter != 'all':
        query = query.filter(Leave.leave_type == leave_type_filter)
    
    # Order: Pending first, then by date (most recent)
    query = query.order_by(
        db.case(
            (Leave.status == 'PENDING', 1),
            (Leave.status == 'APPROVED', 2),
            (Leave.status == 'REJECTED', 3)
        ),
        Leave.applied_on.desc()
    )
    
    # Execute query
    leave_records = query.all()
    
    # Calculate statistics for current year
    current_year = datetime.now().year
    year_start = datetime(current_year, 1, 1).date()
    today = datetime.now().date()
    
    # Pending requests requiring action
    pending_count = Leave.query.filter_by(status='PENDING').count()
    
    # Employees on leave today
    on_leave_today_count = Leave.query.filter(
        Leave.status == 'APPROVED',
        Leave.start_date <= today,
        Leave.end_date >= today
    ).count()
    
    # Total approved days this year
    total_approved_days = db.session.query(db.func.sum(Leave.total_days)).filter(
        Leave.status == 'APPROVED',
        Leave.start_date >= year_start
    ).scalar() or 0
    
    # Upcoming leaves (next 30 days)
    upcoming_date = today + timedelta(days=30)
    upcoming_count = Leave.query.filter(
        Leave.status == 'APPROVED',
        Leave.start_date > today,
        Leave.start_date <= upcoming_date
    ).count()
    
    stats = {
        'pending_requests': pending_count,
        'on_leave_today': on_leave_today_count,
        'approved_days': total_approved_days,
        'upcoming_leaves': upcoming_count
    }
    
    # Get list of all employees for filter dropdown
    employees = User.query.filter_by(role='Employee').order_by(User.username).all()
    
    return render_template('time_off_all.html',
                         user=current_user,
                         leave_records=leave_records,
                         stats=stats,
                         employees=employees,
                         current_filter={'status': status_filter, 'employee': employee_filter, 'type': leave_type_filter},
                         current_year=current_year,
                         today=today)


@app.route('/time-off/request', methods=['POST'])
@login_required
def request_time_off():
    """Submit a new time-off request - Employees only"""
    current_user = User.query.get(session['user_id'])
    if not current_user:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    # Only employees can request leave
    if current_user.role in ['Admin', 'HR Officer']:
        return jsonify({'success': False, 'message': 'Admin and HR Officer cannot request leave through this portal.'}), 403
    
    try:
        # Get form data
        leave_type = request.form.get('leave_type')  # PAID, SICK, UNPAID
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
        reason = request.form.get('reason', '').strip()
        attachment = request.files.get('attachment')
        
        # Validate inputs
        if not all([leave_type, start_date_str, end_date_str, reason]):
            return jsonify({'success': False, 'message': 'All fields are required.'}), 400
        
        if leave_type not in ['PAID', 'SICK', 'UNPAID']:
            return jsonify({'success': False, 'message': 'Invalid leave type.'}), 400
        
        if len(reason) > 500:
            return jsonify({'success': False, 'message': 'Reason must be 500 characters or less.'}), 400
        
        # Parse dates
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'success': False, 'message': 'Invalid date format.'}), 400
        
        # Validation: End date must not be before start date
        if end_date < start_date:
            return jsonify({'success': False, 'message': 'End date cannot be before start date.'}), 400
        
        # Validation: Cannot apply for past dates
        today = datetime.now().date()
        if start_date < today:
            return jsonify({'success': False, 'message': 'Cannot apply for past dates.'}), 400
        
        # Calculate total days
        total_days = (end_date - start_date).days + 1
        
        # Get leave type configuration
        leave_config = Leave.get_leave_type_config(leave_type)
        
        # Validation: Check if attachment is required
        if leave_config['requires_attachment'] and not attachment:
            return jsonify({'success': False, 'message': f'{leave_type} leave requires medical certificate attachment.'}), 400
        
        # Validation: Check leave balance (for PAID and SICK)
        if leave_config['max_days'] is not None:
            current_year = start_date.year
            balance = LeaveBalance.query.filter_by(
                user_id=current_user.id,
                leave_type=leave_type,
                year=current_year
            ).first()
            
            if not balance:
                LeaveBalance.initialize_balance(current_user.id, current_year)
                balance = LeaveBalance.query.filter_by(
                    user_id=current_user.id,
                    leave_type=leave_type,
                    year=current_year
                ).first()
            
            if balance.available_days < total_days:
                return jsonify({
                    'success': False,
                    'message': f'Insufficient {leave_type} leave balance. Available: {balance.available_days} days, Requested: {total_days} days.'
                }), 400
        
        # Validation: Check for overlapping leaves
        overlapping = Leave.query.filter(
            Leave.user_id == current_user.id,
            Leave.status.in_(['PENDING', 'APPROVED']),
            db.or_(
                db.and_(Leave.start_date <= start_date, Leave.end_date >= start_date),
                db.and_(Leave.start_date <= end_date, Leave.end_date >= end_date),
                db.and_(Leave.start_date >= start_date, Leave.end_date <= end_date)
            )
        ).first()
        
        if overlapping:
            return jsonify({
                'success': False,
                'message': f'Overlapping leave found: {overlapping.leave_type} from {overlapping.start_date} to {overlapping.end_date}.'
            }), 400
        
        # Handle attachment upload (if provided)
        attachment_filename = None
        if attachment and attachment.filename:
            # Secure filename and save
            from werkzeug.utils import secure_filename
            import os
            
            filename = secure_filename(attachment.filename)
            # Create uploads directory if it doesn't exist
            upload_dir = os.path.join(app.root_path, 'static', 'uploads', 'leave_attachments')
            os.makedirs(upload_dir, exist_ok=True)
            
            # Generate unique filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            attachment_filename = f"{current_user.id}_{timestamp}_{filename}"
            attachment_path = os.path.join(upload_dir, attachment_filename)
            attachment.save(attachment_path)
        
        # Create leave request
        new_leave = Leave(
            user_id=current_user.id,
            leave_type=leave_type,
            start_date=start_date,
            end_date=end_date,
            total_days=total_days,
            reason=reason,
            status='PENDING',
            is_paid=leave_config['is_paid'],
            attachment_file=attachment_filename
        )
        
        db.session.add(new_leave)
        db.session.commit()
        
        flash(f'{leave_type} leave request submitted successfully. Status: Pending approval.', 'success')
        return jsonify({
            'success': True,
            'message': 'Leave request submitted successfully.',
            'leave_id': new_leave.id
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error submitting request: {str(e)}'}), 500


@app.route('/time-off/approve/<int:leave_id>', methods=['POST'])
@login_required
def approve_time_off(leave_id):
    """Approve a time-off request - Admin/HR only"""
    current_user = User.query.get(session['user_id'])
    if not current_user:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    # Only Admin and HR Officer can approve
    if current_user.role not in ['Admin', 'HR Officer']:
        return jsonify({'success': False, 'message': 'You do not have permission to approve leave requests.'}), 403
    
    try:
        leave = Leave.query.get(leave_id)
        if not leave:
            return jsonify({'success': False, 'message': 'Leave request not found.'}), 404
        
        # Only pending requests can be approved
        if leave.status != 'PENDING':
            return jsonify({'success': False, 'message': f'Cannot approve a {leave.status} request.'}), 400
        
        # Check if already locked (for payroll integration)
        if leave.is_locked:
            return jsonify({'success': False, 'message': 'This leave request is locked for payroll processing.'}), 400
        
        # Get optional comment
        data = request.get_json() or {}
        comment = data.get('comment', '').strip()
        
        # Update leave status
        leave.status = 'APPROVED'
        leave.reviewed_by = current_user.id
        leave.reviewed_at = datetime.now()
        leave.updated_at = datetime.now()
        
        if comment:
            leave.reason = f"{leave.reason}\n\nAdmin Comment: {comment}"
        
        # Deduct from leave balance (for PAID and SICK leave)
        leave_config = Leave.get_leave_type_config(leave.leave_type)
        if leave_config['max_days'] is not None:
            balance = LeaveBalance.query.filter_by(
                user_id=leave.user_id,
                leave_type=leave.leave_type,
                year=leave.start_date.year
            ).first()
            
            if balance:
                balance.deduct(leave.total_days)
        
        # Create attendance records for the approved leave period
        current_date = leave.start_date
        while current_date <= leave.end_date:
            # Check if attendance record already exists
            existing = Attendance.query.filter_by(
                user_id=leave.user_id,
                date=current_date
            ).first()
            
            if not existing:
                # Create new attendance record marked as LEAVE
                attendance = Attendance(
                    user_id=leave.user_id,
                    date=current_date,
                    status='LEAVE',
                    check_in=None,
                    check_out=None,
                    break_minutes=0,
                    work_hours=0.0,
                    extra_hours=0.0
                )
                db.session.add(attendance)
            
            current_date += timedelta(days=1)
        
        db.session.commit()
        
        flash(f'Leave request approved for {leave.user.username}.', 'success')
        return jsonify({
            'success': True,
            'message': 'Leave request approved successfully.',
            'leave_id': leave.id
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error approving request: {str(e)}'}), 500


@app.route('/time-off/reject/<int:leave_id>', methods=['POST'])
@login_required
def reject_time_off(leave_id):
    """Reject a time-off request - Admin/HR only"""
    current_user = User.query.get(session['user_id'])
    if not current_user:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    # Only Admin and HR Officer can reject
    if current_user.role not in ['Admin', 'HR Officer']:
        return jsonify({'success': False, 'message': 'You do not have permission to reject leave requests.'}), 403
    
    try:
        leave = Leave.query.get(leave_id)
        if not leave:
            return jsonify({'success': False, 'message': 'Leave request not found.'}), 404
        
        # Only pending requests can be rejected
        if leave.status != 'PENDING':
            return jsonify({'success': False, 'message': f'Cannot reject a {leave.status} request.'}), 400
        
        # Check if already locked
        if leave.is_locked:
            return jsonify({'success': False, 'message': 'This leave request is locked for payroll processing.'}), 400
        
        # Get mandatory rejection reason
        data = request.get_json() or {}
        comment = data.get('comment', '').strip()
        
        if not comment:
            return jsonify({'success': False, 'message': 'Rejection reason is required.'}), 400
        
        # Update leave status
        leave.status = 'REJECTED'
        leave.reviewed_by = current_user.id
        leave.reviewed_at = datetime.now()
        leave.updated_at = datetime.now()
        leave.reason = f"{leave.reason}\n\nRejection Reason: {comment}"
        
        db.session.commit()
        
        flash(f'Leave request rejected for {leave.user.username}.', 'info')
        return jsonify({
            'success': True,
            'message': 'Leave request rejected.',
            'leave_id': leave.id
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error rejecting request: {str(e)}'}), 500


@app.route('/time-off/cancel/<int:leave_id>', methods=['POST'])
@login_required
def cancel_time_off(leave_id):
    """Cancel own time-off request - Employees can cancel PENDING requests only"""
    current_user = User.query.get(session['user_id'])
    if not current_user:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        leave = Leave.query.get(leave_id)
        if not leave:
            return jsonify({'success': False, 'message': 'Leave request not found.'}), 404
        
        # Employees can only cancel their own requests
        if leave.user_id != current_user.id and current_user.role not in ['Admin', 'HR Officer']:
            return jsonify({'success': False, 'message': 'You can only cancel your own requests.'}), 403
        
        # Can only cancel PENDING requests
        if leave.status != 'PENDING':
            return jsonify({'success': False, 'message': 'Only pending requests can be cancelled.'}), 400
        
        # Check if locked
        if leave.is_locked:
            return jsonify({'success': False, 'message': 'This request is locked and cannot be cancelled.'}), 400
        
        # Delete the leave request
        db.session.delete(leave)
        db.session.commit()
        
        flash('Leave request cancelled successfully.', 'success')
        return jsonify({
            'success': True,
            'message': 'Leave request cancelled successfully.'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error cancelling request: {str(e)}'}), 500


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
    
    # Permission check - strict enforcement
    is_self = (user.id == viewer.id)
    is_hr_admin = viewer.role in ['Admin', 'HR Officer']
    
    # Employees can ONLY edit their own profile
    if viewer.role == 'Employee' and not is_self:
        return jsonify({'success': False, 'message': 'Unauthorized: Employees cannot edit other profiles'}), 403
    
    if not (is_self or is_hr_admin):
        return jsonify({'success': False, 'message': 'Unauthorized: Insufficient permissions'}), 403
    
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
    """
    Update salary information (ADMIN & HR - Critical Access Control)
    =================================================================
    Implements:
    - RBAC enforcement at backend
    - Component-based calculation
    - Validation rules (sum = wage)
    - Auto-balance Fixed Allowance
    - PF calculation on Basic only
    """
    viewer = User.query.get(session['user_id'])
    user = User.query.get(user_id)
    
    # Enforce: Only Admin and HR Officers can manage salary
    if viewer.role not in ['Admin', 'HR Officer']:
        flash('Access denied. Only administrators and HR officers can manage salary information.', 'error')
        return redirect(url_for('employees'))
    
    if not user or user.role != 'Employee':
        flash('Invalid user or user is not an employee.', 'error')
        return redirect(url_for('employees'))
    
    try:
        # Validate wage input
        monthly_wage = float(request.form.get('monthly_wage', 0))
        if monthly_wage <= 0:
            flash('Monthly wage must be greater than zero.', 'error')
            return redirect(url_for('profile', user_id=user_id))
        
        # Get or create salary record
        salary = Salary.query.filter_by(user_id=user_id).first()
        if not salary:
            salary = Salary(user_id=user_id)
            db.session.add(salary)
        
        # Check if locked (payroll processed)
        if salary.is_locked:
            flash('Salary is locked. Cannot modify after payroll has been processed.', 'error')
            return redirect(url_for('profile', user_id=user_id))
        
        # Update core wage
        old_wage = salary.monthly_wage if salary.monthly_wage else 0
        salary.monthly_wage = monthly_wage
        
        # Update working schedule metadata
        salary.working_days_per_week = int(request.form.get('working_days_per_week', 5))
        salary.daily_working_hours = float(request.form.get('daily_hours', 8.0))
        salary.break_time_hours = float(request.form.get('break_hours', 1.0))
        
        # Update PF percentages (validated)
        employee_pf = float(request.form.get('employee_pf_percent', 12.0))
        employer_pf = float(request.form.get('employer_pf_percent', 12.0))
        
        if employee_pf < 0 or employee_pf > 100:
            flash('Employee PF percentage must be between 0 and 100.', 'error')
            return redirect(url_for('profile', user_id=user_id))
        
        if employer_pf < 0 or employer_pf > 100:
            flash('Employer PF percentage must be between 0 and 100.', 'error')
            return redirect(url_for('profile', user_id=user_id))
        
        salary.employee_pf_percent = employee_pf
        salary.employer_pf_percent = employer_pf
        
        # Update professional tax
        prof_tax = float(request.form.get('professional_tax', 200.0))
        if prof_tax < 0:
            flash('Professional tax cannot be negative.', 'error')
            return redirect(url_for('profile', user_id=user_id))
        
        salary.professional_tax = prof_tax
        
        # Update standard allowance if provided (configurable)
        standard_allowance = request.form.get('standard_allowance')
        if standard_allowance:
            salary.standard_allowance = float(standard_allowance)
        
        # ✨ Backend Calculation Flow (Auto-recalculate all components)
        salary.calculate_breakdown()
        
        # ✅ Validate components (sum = wage)
        try:
            salary.validate_components()
        except ValueError as ve:
            flash(f'Validation failed: {str(ve)}', 'error')
            db.session.rollback()
            return redirect(url_for('profile', user_id=user_id))
        
        # Commit changes
        db.session.commit()
        
        # Success message with details
        if old_wage != monthly_wage:
            flash(f'Salary updated successfully! Wage changed from ₹{old_wage:,.2f} to ₹{monthly_wage:,.2f}. All components recalculated.', 'success')
        else:
            flash('Salary information updated successfully!', 'success')
        
    except ValueError as ve:
        db.session.rollback()
        flash(f'Invalid input: {str(ve)}', 'error')
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

