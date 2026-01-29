"""Test email sending functionality"""
from app import app, mail, Message

def test_email():
    with app.app_context():
        try:
            print("📧 Testing email sending...")
            print(f"From: {app.config['MAIL_USERNAME']}")
            print(f"To: jayraychura13@gmail.com")
            
            msg = Message(
                subject='Test Email - Dayflow HRMS',
                recipients=['jayraychura13@gmail.com']
            )
            msg.body = 'This is a test email from Dayflow HRMS to verify email functionality.'
            msg.html = '''
            <html>
            <body style="font-family: Arial, sans-serif;">
                <h2>✅ Email Test Successful!</h2>
                <p>This is a test email from Dayflow HRMS.</p>
                <p>If you're seeing this, email sending is working correctly!</p>
            </body>
            </html>
            '''
            
            mail.send(msg)
            print("✅ Test email sent successfully!")
            print("✅ Email sending is working!")
            print("\n📬 Please check your inbox: jayraychura13@gmail.com")
            return True
            
        except Exception as e:
            print(f"❌ Email sending failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == '__main__':
    test_email()
