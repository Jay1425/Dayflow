# Quick Start Guide: Forgot Password Feature

## 🚀 How to Use

### For Users:

1. **Access the Forgot Password Page**
   - Go to the login page: `http://localhost:5000/login`
   - Click on "Forgot password?" link

2. **Request Password Reset**
   - Enter your registered email address
   - Click "Send Reset Link"
   - Check your email inbox

3. **Reset Your Password**
   - Open the email from Dayflow HRMS
   - Click the "Reset Your Password" button
   - Enter your new password (must meet security requirements)
   - Confirm the new password
   - Click "Reset Password"

4. **Login with New Password**
   - You'll be redirected to the login page
   - Use your login ID/email and new password
   - Access your account!

## 📋 Password Requirements

Your new password must include:
- ✅ At least 8 characters
- ✅ One uppercase letter (A-Z)
- ✅ One lowercase letter (a-z)
- ✅ One number (0-9)
- ✅ One special character (!@#$%^&*(),.?":{}|<>)

## ⚠️ Important Notes

- **Link Expiration**: Password reset links expire after 1 hour
- **One-Time Use**: Each reset link can only be used once
- **Security**: Never share your reset link with anyone
- **Email Check**: Make sure to check your spam folder if you don't see the email

## 🎨 UI Features

The forgot password pages include:
- 🔐 Modern, secure interface matching Dayflow's design
- 💪 Real-time password strength indicator
- 👁️ Password visibility toggle
- ✨ Visual feedback for password requirements
- 📱 Responsive design for all devices
- 🌈 Gradient backgrounds and smooth animations

## 🔧 For Administrators

### Email Configuration
The feature requires proper email configuration in `.env`:
```env
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=your-email@gmail.com
```

### Testing
Test the feature with existing users:
- Admin: `jayraychura22@gmail.com`
- Or any registered user email

### Monitoring
Check logs for:
- Email sending status (success/failure)
- Token generation
- Password reset attempts

## 🎯 Routes Added

- `/forgot_password` - Request password reset
- `/reset_password/<token>` - Reset password with token

## ✅ Features Checklist

- [x] Forgot password link on login page
- [x] Email input form with validation
- [x] Secure token generation
- [x] Email delivery with reset link
- [x] Token expiration (1 hour)
- [x] Password strength validation
- [x] Real-time password feedback
- [x] Password confirmation matching
- [x] Secure password hashing
- [x] Single-use tokens
- [x] Responsive design
- [x] Error handling
- [x] User feedback messages

## 🐛 Troubleshooting

**Problem**: Not receiving reset email
- Check spam/junk folder
- Verify email is registered in system
- Check email configuration in `.env`
- Review server logs for email errors

**Problem**: Reset link expired
- Request a new reset link
- Links expire after 1 hour for security

**Problem**: Password not accepted
- Ensure all password requirements are met
- Check that passwords match
- Try a different password

## 📞 Support

If you encounter issues:
1. Check this guide first
2. Review error messages carefully
3. Contact your system administrator
4. Check the application logs

---

**Status**: ✅ Feature fully implemented and ready to use!
**Version**: 1.0
**Last Updated**: January 26, 2026
