# HackathonApp

A modern, feature-rich web application built with Flask, featuring user authentication, Google OAuth integration, and a beautiful glassmorphism UI design.

## ✨ Features

- 🔐 **User Authentication** - Secure signup and login system
- 🌐 **Google OAuth Integration** - Sign in with Google account
- 💾 **SQLite Database** - User data management with SQLAlchemy
- 🎨 **Modern UI** - Beautiful glassmorphism design with Tailwind CSS
- 📱 **Responsive Design** - Works seamlessly on all devices
- 🔒 **Password Security** - Bcrypt password hashing
- 📊 **User Dashboard** - Personalized user dashboard
- ✉️ **Flash Messages** - User-friendly notifications

## 🚀 Quick Start

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- Git (optional)

### Installation

1. **Clone or download the repository**
   ```bash
   git clone <repository-url>
   cd odoo_gcet
   ```

2. **Create a virtual environment (recommended)**
   ```bash
   python -m venv .venv
   ```

3. **Activate the virtual environment**
   - Windows:
     ```bash
     .venv\Scripts\activate
     ```
   - Linux/Mac:
     ```bash
     source .venv/bin/activate
     ```

4. **Install required packages**
   ```bash
   pip install -r requirements.txt
   ```

5. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```
   Then edit `.env` file with your configuration (see Configuration section below)

6. **Run the application**
   ```bash
   python app.py
   ```

7. **Open your browser**
   Navigate to `http://localhost:5000`

## ⚙️ Configuration

### Basic Setup

Edit the `.env` file with your settings:

```env
SECRET_KEY=your-secret-key-here
FLASK_ENV=development
DEBUG=True
```

### Google OAuth Setup (Optional)

To enable Google Sign-In:

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Navigate to **APIs & Services** > **Credentials**
4. Create OAuth 2.0 Client ID
5. Add authorized origins:
   - `http://localhost:5000`
   - `http://127.0.0.1:5000`
6. Copy your Client ID and add to `.env`:
   ```env
   GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
   ```

For detailed Google OAuth setup, see [GOOGLE_OAUTH_SETUP.md](GOOGLE_OAUTH_SETUP.md)

## 📖 Usage

### Creating an Account

1. Click **Sign Up** in the navigation bar
2. Fill in your details:
   - Full Name
   - Username
   - Email Address
   - Password (minimum 8 characters)
3. Accept the Terms of Service
4. Click **Create Account**

**Or** use **Sign up with Google** for quick registration

### Logging In

1. Click **Login** in the navigation bar
2. Enter your username and password
3. Click **Sign In**

**Or** use **Sign in with Google**

**Demo Account:**
- Username: `demo`
- Password: `password`

### Using the Dashboard

After logging in, you can:
- View your profile information
- See account statistics
- Access personalized features
- Update your profile

### Logging Out

Click **Logout** in the navigation bar to end your session

## 📁 Project Structure

```
odoo_gcet/
├── app.py                      # Main Flask application
├── requirements.txt            # Python dependencies
├── .env.example               # Environment variables template
├── GOOGLE_OAUTH_SETUP.md      # Google OAuth setup guide
├── README.md                  # This file
├── app.db                     # SQLite database (auto-created)
├── static/
│   ├── css/
│   │   └── style.css         # Custom styles
│   └── js/
│       └── main.js           # JavaScript functionality
└── templates/
    ├── base.html             # Base template
    ├── index.html            # Home page
    ├── about.html            # About page
    ├── login.html            # Login page
    ├── signup.html           # Signup page
    ├── dashboard.html        # User dashboard
    ├── profile.html          # User profile
    └── 404.html              # Error page
```

## 🛠️ Development

### Database

The application uses SQLite database (`app.db`) which is automatically created on first run. The database includes a demo user for testing.

### Adding New Features

1. Define routes in `app.py`
2. Create templates in `templates/` directory
3. Add styles in `static/css/style.css`
4. Add JavaScript in `static/js/main.js`

### Database Models

Current models:
- **User Model**: id, fullname, username, email, password_hash, newsletter, created_at

## 🔒 Security Features

- ✅ Password hashing with Werkzeug security
- ✅ Session management
- ✅ CSRF protection
- ✅ Secure password validation (minimum 8 characters)
- ✅ SQL injection prevention via SQLAlchemy ORM
- ✅ Google OAuth 2.0 authentication

## 🎨 Tech Stack

- **Backend:** Flask 3.0.0
- **Database:** SQLite with SQLAlchemy
- **Frontend:** HTML5, Tailwind CSS, JavaScript
- **Authentication:** Flask sessions + Google OAuth
- **Icons:** Font Awesome 6.4.0
- **Fonts:** Inter & Poppins (Google Fonts)

## 📝 API Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Home page |
| `/about` | GET | About page |
| `/login` | GET, POST | Login page |
| `/signup` | GET, POST | Signup page |
| `/google-login` | POST | Google OAuth callback |
| `/dashboard` | GET | User dashboard (protected) |
| `/profile` | GET | User profile (protected) |
| `/logout` | GET | Logout user |

## 🐛 Troubleshooting

### Common Issues

**Port already in use:**
```bash
# Change port in app.py or use:
python app.py --port 5001
```

**Database locked:**
```bash
# Stop all Flask instances and restart
```

**Google Sign-In not working:**
- Verify Client ID is correct in `.env` and template files
- Check authorized origins in Google Cloud Console
- Ensure HTTPS is used in production

**Module not found errors:**
```bash
pip install -r requirements.txt
```

## 📄 License

This project is open source and available for educational purposes.

## 👥 Contributing

Contributions are welcome! Feel free to submit issues and pull requests.

## 📧 Support

For issues and questions, please create an issue in the repository or contact the development team.

## 🔄 Updates

- **v1.0.0** - Initial release with basic authentication
- **v1.1.0** - Added Google OAuth integration
- **v1.2.0** - Enhanced UI with glassmorphism design

---

**Built with ❤️ using Flask and modern web technologies**
