# Google OAuth Setup Instructions

## Step 1: Create Google OAuth Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to **APIs & Services** > **Credentials**
4. Click **+ CREATE CREDENTIALS** > **OAuth client ID**
5. If prompted, configure the OAuth consent screen:
   - Select **External** user type
   - Fill in app name: "HackathonApp"
   - Add your email as support email
   - Click **Save and Continue**
6. Back to creating OAuth client ID:
   - Application type: **Web application**
   - Name: "HackathonApp Web Client"
   - Authorized JavaScript origins:
     - `http://localhost:5000`
     - `http://127.0.0.1:5000`
   - Authorized redirect URIs:
     - `http://localhost:5000/google-login`
     - `http://127.0.0.1:5000/google-login`
7. Click **Create**
8. Copy your **Client ID** (it looks like: `xxxxx.apps.googleusercontent.com`)

## Step 2: Install Required Python Packages

```bash
pip install google-auth google-auth-oauthlib google-auth-httplib2 requests cachecontrol
```

## Step 3: Update Configuration Files

### Update app.py
Replace `YOUR_GOOGLE_CLIENT_ID` with your actual Google Client ID:
```python
GOOGLE_CLIENT_ID = "your-actual-client-id.apps.googleusercontent.com"
```

### Update login.html
Replace `YOUR_GOOGLE_CLIENT_ID` on line ~90:
```html
data-client_id="your-actual-client-id.apps.googleusercontent.com"
```

### Update signup.html
Replace `YOUR_GOOGLE_CLIENT_ID` on line ~151:
```html
data-client_id="your-actual-client-id.apps.googleusercontent.com"
```

## Step 4: Test the Integration

1. Run your Flask app:
   ```bash
   python app.py
   ```

2. Navigate to `http://localhost:5000/login` or `http://localhost:5000/signup`

3. Click the "Sign in with Google" button

4. You should see the Google login popup

## Features Implemented

- ✅ Google Sign-In button on login page
- ✅ Google Sign-Up button on signup page
- ✅ Automatic user creation for new Google users
- ✅ Automatic login for existing users
- ✅ Beautiful UI integration with your existing design

## Security Notes

- The line `os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'` is for **development only**
- Remove it or set to '0' when deploying to production with HTTPS
- Never commit your actual Google Client ID to public repositories
- Consider using environment variables for sensitive configuration

## Troubleshooting

- **Error: "Invalid Google token"** - Make sure your Client ID matches in all files
- **Button doesn't appear** - Check browser console for JavaScript errors
- **Redirect fails** - Verify authorized redirect URIs in Google Console
