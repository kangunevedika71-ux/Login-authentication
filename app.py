from flask import Flask, render_template,url_for,request,redirect,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin,login_user,login_required,current_user,logout_user
from sqlalchemy import text
import re
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash,check_password_hash
from urllib.parse import urlparse
from datetime import timedelta
db = SQLAlchemy()
login_manager = LoginManager()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)

    def __repr__(self):
        return f"<User {self.username}>"


def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = 'ved-secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///app.db"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=15)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"

    # CREATE TABLES
    with app.app_context():
        db.create_all()

    @app.route("/health/do")
    def health_db():
        try:
            db.session.execute(text("SELECT 1"))
            return {"db": "ok"}, 200
        except Exception as e:
            return {"db": "error", "detail": str(e)}, 500
        
        
    def _is_safe_local_path(target:str) -> bool:
        if not target:
            return False
        parts = urlparse(target)
        return parts.scheme == "" and parts.netloc == "" and target.startswith("/")

    @app.route("/")
    def index():
        return render_template("index.html")
    
    
    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html")
    
    
    @app.route("/test")
    @login_required
    def test():
        return "text route"

    
    @app.route("/register/", methods=["GET", "POST"])
    def register():
        errors = []

        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            email = (request.form.get("email") or "").strip()
            password = (request.form.get("password") or "")
            confirm = (request.form.get("confirm_password") or "")

            if not (3 <= len(username) <= 100):
                errors.append("Username must be between 3 and 100 characters!")

            if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
                errors.append("Please enter a valid email address!")

            if len(password) < 6:
                errors.append("Password must be at least 6 characters!")

            if password != confirm:
                errors.append("Passwords do not match!")

            if not errors:
                try:
                    pw_hash = generate_password_hash(password)

                    user = User(
                        username=username,
                        email=email,
                        password_hash=pw_hash
                    )

                    db.session.add(user)
                    db.session.commit()
                    
                    flash("Account created successfully !,Please login","success")

                    return redirect(url_for('login'))

                except IntegrityError:
                    db.session.rollback()
                    errors.append("That username or email is already registered!")

        return render_template("register.html", errors=errors)

    @app.route("/login",methods=["POST","GET"])
    def login():
        
        errors = []
        if request.method=="POST":
            email = (request.form.get("email") or "").strip()
            password = (request.form.get("password") or "")
            
            if not email:
                errors.append("Emaail is required")
                
            if not password:
                errors.append("Password is required")
                
            if not errors:
                user = User.query.filter_by(email=email).first()
                    
                    
            if not user or not check_password_hash(user.password_hash,password):
                errors.append("Invalid email or password")
                
            else:
                
                remembar_flag=request.form.get("remember")=="1"
                
                login_user(user,remember=remembar_flag)
                flash(f"Welcome back {user.username}","success")
                
                
                
                
                
                next_url = request.form.get("next") or request.args.get("next") or ""
                if _is_safe_local_path(next_url):
                    return redirect(next_url)
                
                return redirect(url_for("dashboard"))
                    
        
        return render_template("login.html",errors=errors)
    
    @app.route("/logout")
    def logout():
        logout_user()
        flash("you have been logged out","success")
        return redirect(url_for("index"))
    
    @app.route("/changepassword",methods=["GET","POST"])
    def change_password():
        errors=[]
        if request.method=="POST":
            current_pw=request.form.get("current_password") or ""
            new_pw=request.form.get("new_password") or ""
            confirm_pw=request.form.get("confirm_password") or ""
            
            if not check_password_hash(current_user.password_hash,current_pw):
                errors.append("Current password is incorrect !")
                
            if len(new_pw) < 6:
                errors.append("New passwords need to be at least 6 characters !")
                
            if new_pw !=confirm_pw:
                errors.append("New passwords and confirmation  do not match !")
                
            if not errors:
                current_user.password_hash = generate_password_hash(new_pw)
                db.session.commit()
                
                flash("you password has been updated !","success")
                return redirect(url_for("dashboard"))
            
        return render_template("change_password.html",errors=errors)
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    
    return app

    

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)