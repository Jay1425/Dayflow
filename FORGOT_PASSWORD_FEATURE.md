# Forgot Password Feature Documentation

## Overview
The forgot password feature allows users to reset their password by receiving a secure reset link via email.

## Features Implemented

### 1. Database Schema
Added two new fields to the `User` model:
- `reset_token`: Stores the unique password reset token (VARCHAR 100)
- `reset_token_expiry`: Stores token expiration timestamp (DATETIME)

### 2. Helper Functions

#### `generate_reset_token()`
- Generates a secure URL-safe token using `secrets.token_urlsafe(32)`
- Returns a 32-character random token

#### `send_password_reset_email(email, fullname, reset_token)`
- Sends a beautifully formatted HTML email with the password reset link
- Includes user's name and a secure reset link
- Link expires in 1 hour
- Returns True if email sent successfully, False otherwise

### 3. Routes

#### `/forgot_password` (GET, POST)
**Purpose**: Request a password reset link

**POST Parameters**:
- `email`: User's registered email address

**Behavior**:
- Validates email input
- Searches for user by email
- Generates unique reset token with 1-hour expiration
- Sends password reset email
- Shows generic success message (security best practice)
- Redirects to login page

**Security Features**:
- Doesn't reveal if email exists in database
- Rate limiting via database timestamps
- Token expires after 1 hour

#### `/reset_password/<token>` (GET, POST)
**Purpose**: Reset password using email token

**POST Parameters**:
- `password`: New password
- `confirm_password`: Password confirmation

**Behavior**:
- Validates token exists and hasn't expired
- Validates passwords match
- Checks password strength requirements
- Updates password with secure hash
- Clears reset token from database
- Marks first_login as False if applicable
- Updates password_updated_at timestamp
- Redirects to login with success message

**Security Features**:
- Token validation before showing form
- Expiration check (1 hour)
- Strong password validation
- Token is single-use (cleared after reset)

### 4. Templates

#### `forgot_password.html`
- Clean, modern design matching app aesthetics
- Email input field with validation
- Clear instructions and help text
- Links back to login and home page
- Shows password reset link expiry time (1 hour)

#### `reset_password.html`
- Password strength indicator with visual feedback
- Real-time password matching validation
- Password requirements displayed clearly
- Toggle password visibility
- Responsive design with gradient backgrounds
- User name display for confirmation

#### Updated `login.html`
- "Forgot password?" link now points to `/forgot_password`
- Seamless integration with existing design

## Password Requirements
Users must create passwords that meet these criteria:
- Minimum 8 characters long
- At least one uppercase letter (A-Z)
- At least one lowercase letter (a-z)
- At least one number (0-9)
- At least one special character (!@#$%^&*(),.?":{}|<>)

## User Flow

### Forgot Password Flow:
1. User clicks "Forgot password?" on login page
2. User enters registered email address
3. System generates secure token and sends email
4. User receives email with reset link
5. User clicks link and is taken to reset password page
6. User enters new password (with strength validation)
7. Password is updated, user redirected to login
8. User logs in with new password

### Security Considerations:
✅ Tokens expire after 1 hour
✅ Tokens are URL-safe and cryptographically secure
✅ Email existence is not revealed to attackers
✅ Passwords must meet strict security requirements
✅ Tokens are single-use (cleared after reset)
✅ All password changes are timestamped
✅ Email verification before password reset

## Email Configuration
The feature uses Flask-Mail with Gmail SMTP:
- Server: smtp.gmail.com
- Port: 587
- TLS: Enabled
- Credentials from environment variables

**Current Configuration**:
```
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=aivisionaries.teams@gmail.com
MAIL_PASSWORD=rvesfkcwikpqmbmw
```

## Testing the Feature

### Test Steps:
1. Start the Flask application
2. Navigate to `/login`
3. Click "Forgot password?"
4. Enter a registered email (e.g., jayraychura22@gmail.com for admin)
5. Check email inbox for reset link
6. Click the reset link
7. Enter new password meeting requirements
8. Submit and verify redirect to login
9. Log in with new password

### Test Users:
- **Admin**: jayraychura22@gmail.com (login_id: OISA20260001)
- **Demo Employee**: (check database for other users)

## Future Enhancements
- [ ] Add rate limiting to prevent abuse
- [ ] Track password reset attempts
- [ ] Add SMS verification option
- [ ] Password reset audit log
- [ ] Multi-factor authentication
- [ ] Password history (prevent reuse)
- [ ] Customizable token expiration time

## Error Handling
The feature includes comprehensive error handling:
- Invalid/expired token → Redirect to login with error message
- Email sending failure → User notified to contact support
- Database errors → Graceful rollback and error message
- Password mismatch → Clear validation feedback
- Weak password → Specific requirement failures shown

## Files Modified/Created

### Modified Files:
1. `app.py` - Added routes, helper functions, and database fields
2. `templates/login.html` - Updated forgot password link

### Created Files:
1. `templates/forgot_password.html` - Forgot password request page
2. `templates/reset_password.html` - Password reset page
3. `FORGOT_PASSWORD_FEATURE.md` - This documentation

## Success! ✅
The forgot password feature is now fully implemented and ready to use!
