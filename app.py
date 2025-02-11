import os
import sqlite3
import random
import string
import uuid
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# Configure SQLite database
DATABASE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DATABASE_FILE}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Configure Flask-Mail
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("email")
app.config["MAIL_PASSWORD"] = os.getenv("app_password")
mail = Mail(app)

# Google OAuth setup with proper configuration
oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    access_token_params={'grant_type': 'authorization_code'},
    authorize_params={'access_type': 'offline'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'token_endpoint_auth_method': 'client_secret_post'
    }
)

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Resume(db.Model):
    __tablename__ = 'resumes'
    id = db.Column(db.Integer, primary_key=True)
    imglink = db.Column(db.String(200), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    hreflink = db.Column(db.String(200), nullable=False)
    pick = db.Column(db.String(50), nullable=False)
    authorname = db.Column(db.String(100), nullable=False)

class Roadmap(db.Model):
    __tablename__ = 'roadmaps'
    id = db.Column(db.Integer, primary_key=True)
    fieldname = db.Column(db.String(100), nullable=False)
    roadmaplink = db.Column(db.String(200), nullable=False)

class DSAQuestion(db.Model):
    __tablename__ = 'dsa_questions'
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    qsnlink = db.Column(db.String(200), nullable=False)

# Updated user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route("/")
def index():
    return render_template("index.html")

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

@app.route("/send-otp", methods=["POST"])
def send_otp():
    email = request.form.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400

    otp = generate_otp()
    session.update({
        "registration_otp": otp,
        "registration_email": email,
        "otp_timestamp": datetime.utcnow().timestamp(),
    })

    msg = Message(
        "Your OTP for Registration",
        sender=app.config["MAIL_USERNAME"],
        recipients=[email],
    )
    msg.body = f"Your OTP for registration is: {otp}"

    try:
        mail.send(msg)
        return jsonify({"message": "OTP sent successfully"}), 200
    except Exception:
        return jsonify({"error": "Failed to send OTP"}), 500

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        name, email, password, submitted_otp = request.form["name"], request.form["email"], request.form["password"], request.form.get("otp")
        stored_otp, stored_email, otp_timestamp = session.get("registration_otp"), session.get("registration_email"), session.get("otp_timestamp")

        if not stored_otp or (datetime.utcnow().timestamp() - otp_timestamp) > 600:
            flash("OTP expired. Request a new one.", "danger")
            return redirect(url_for("register"))
        
        if email != stored_email or submitted_otp != stored_otp:
            flash("Invalid OTP or Email mismatch.", "danger")
            return redirect(url_for("register"))

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        # Check if the email already exists
        if User.query.filter_by(email=email).first():
            flash("Email already exists", "danger")
            return redirect(url_for("register"))

        try:
            new_user = User(
                name=name,
                email=email,
                password=hashed_password
            )
            db.session.add(new_user)
            db.session.commit()
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            db.session.rollback()
            flash("Email already exists", "danger")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("index"))
        flash("Invalid email or password.", "danger")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# Flask-Admin Setup
class MyAdminIndexView(AdminIndexView):
    @expose("/")
    def index(self):
        if not current_user.is_authenticated or current_user.email != app.config["MAIL_USERNAME"]:
            return "You are not authorized to access this page.", 403
        return super().index()

class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.email == app.config["MAIL_USERNAME"]
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for("login"))

admin = Admin(app, name="Secure Admin", template_mode="bootstrap3", index_view=MyAdminIndexView())

# Add model views to admin
admin.add_view(SecureModelView(User, db.session))
admin.add_view(SecureModelView(Resume, db.session))
admin.add_view(SecureModelView(Roadmap, db.session))
admin.add_view(SecureModelView(DSAQuestion, db.session))

# Routes for database models
@app.route("/qsn")
@login_required
def qsn():
    questions = DSAQuestion.query.all()
    return render_template("qsn.html", questions=questions)

@app.route("/resume")
@login_required
def resume():
    resumes = Resume.query.all()
    return render_template("resume.html", resumes=resumes)

@app.route("/roadmap")
@login_required
def roadmap():
    roadmaps = Roadmap.query.all()
    return render_template("roadmap.html", roadmaps=roadmaps)

# Updated Google OAuth routes with proper error handling
@app.route("/google-login")
def google_login():
    redirect_uri = url_for("auth_callback", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/auth/callback")
def auth_callback():
    try:
        token = google.authorize_access_token()
        user_info = google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()
        
        if not user_info.get("email_verified"):
            flash("Google account not verified", "danger")
            return redirect(url_for("login"))
            
        user = User.query.filter_by(email=user_info["email"]).first()
        
        if not user:
            user = User(
                name=user_info["name"],
                email=user_info["email"],
                password=bcrypt.generate_password_hash(uuid.uuid4().hex).decode('utf-8')
            )
            db.session.add(user)
            db.session.commit()
        
        login_user(user)
        return redirect(url_for("index"))
        
    except Exception as e:
        print(f"Google login error: {str(e)}")
        flash("Google login failed. Please try again.", "danger")
        return redirect(url_for("login"))


if __name__ == "__main__":
  
    app.run(debug=True)
