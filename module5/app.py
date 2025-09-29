from flask import Flask, request, jsonify, abort, redirect, url_for, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from passlib.context import CryptContext
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login_form"

pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")
ts = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ---- login forms ----
@app.get("/register-form")
def register_form():
    return render_template_string("""
    <h1>Register</h1>
    <form method="post" action="/register">
      <label>Name <input name="name" required></label><br>
      <label>Email <input name="email" type="email" required></label><br>
      <label>Password <input name="password" type="password" required></label><br>
      <button>Register</button>
    </form>
    <p><a href="/login-form">Login</a></p>
    """)

@app.get("/login-form")
def login_form():
    return render_template_string("""
    <h1>Login</h1>
    <form method="post" action="/login">
      <label>Email <input name="email" type="email" required></label><br>
      <label>Password <input name="password" type="password" required></label><br>
      <button>Log in</button>
    </form>
    <p><a href="/">Home</a> | <a href="/register-form">Register</a></p>
    """)

# ---------- Models ----------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    roles = db.Column(db.String(255), default="user")  # comma-separated roles

    def set_password(self, password: str):
        self.password_hash = pwd_context.hash(password)

    def check_password(self, password: str) -> bool:
        return pwd_context.verify(password, self.password_hash)

    def has_role(self, role: str) -> bool:
        return role in (self.roles or "").split(",")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------- Decorators ----------
def role_required(role):
    def decorator(fn):
        @login_required
        def wrapper(*args, **kwargs):
            if not current_user.has_role(role):
                abort(403)
            return fn(*args, **kwargs)
        wrapper.__name__ = fn.__name__
        return wrapper
    return decorator

# ---------- Helper ----------
def json_user(u: User):
    return {"id": u.id, "email": u.email, "name": u.name, "roles": u.roles}

# ---------- Routes ----------
@app.route("/")
def index():
    if current_user.is_authenticated:
        return jsonify({"status": "ok", "message": "Logged in", "me": json_user(current_user)})
    return jsonify({"status": "ok", "message": "Not logged in"})

@app.route("/register", methods=["POST"])
def register_api():
    data = request.get_json(silent=True) or request.form
    email = (data.get("email") or "").strip().lower()
    name = (data.get("name") or "").strip()
    password = data.get("password")
    if not email or not name or not password:
        return jsonify({"error": "email, name, password required"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "email already registered"}), 409
    u = User(email=email, name=name)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    return jsonify({"created": True, "user": json_user(u)}), 201

@app.route("/login", methods=["POST"])
def login_api():
    data = request.get_json(silent=True) or request.form
    email = (data.get("email") or "").strip().lower()
    password = data.get("password")
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        login_user(user)
        return jsonify({"login": "ok", "user": json_user(user)})
    return jsonify({"error": "invalid credentials"}), 401

@app.route("/logout")
@login_required
def logout_api():
    logout_user()
    return jsonify({"logout": "ok"})

@app.route("/profile/<int:user_id>")
@login_required
def profile(user_id):
    if current_user.id != user_id and not current_user.has_role("admin"):
        abort(403)
    u = User.query.get_or_404(user_id)
    return jsonify({"profile": json_user(u)})

@app.route("/admin")
@role_required("admin")
def admin_list():
    users = User.query.order_by(User.id).all()
    return jsonify({"users": [json_user(u) for u in users]})

@app.route("/account/<int:user_id>")
@login_required
def get_account(user_id):
    if current_user.id != user_id and not current_user.has_role("admin"):
        abort(403)
    u = User.query.get_or_404(user_id)
    return jsonify({"account": json_user(u)})

@app.route("/request-reset", methods=["POST"])
def request_reset():
    data = request.get_json(silent=True) or request.form
    email = (data.get("email") or "").strip().lower()
    user = User.query.filter_by(email=email).first()
    if user:
        token = ts.dumps({"uid": user.id})
        reset_link = url_for("reset_with_token", token=token, _external=True)
        app.logger.info("Password reset link for %s: %s", email, reset_link)
    return jsonify({"message": "If the email exists, we sent a reset link."})

@app.route("/reset/<token>", methods=["POST"])
def reset_with_token(token):
    try:
        data = ts.loads(token, max_age=3600)
        uid = data["uid"]
    except SignatureExpired:
        return jsonify({"error": "reset link expired"}), 400
    except BadSignature:
        abort(400)
    user = User.query.get_or_404(uid)
    body = request.get_json(silent=True) or request.form
    new_password = body.get("password")
    if not new_password:
        return jsonify({"error": "password required"}), 400
    user.set_password(new_password)
    db.session.commit()
    return jsonify({"password": "updated"})

# ---------- CLI ----------
@app.cli.command("init-db")
def init_db():
    db.create_all()
    if not User.query.filter_by(email="admin@example.com").first():
        admin = User(email="admin@example.com", name="Admin", roles="admin,user")
        admin.set_password("AdminPassw0rd!")
        db.session.add(admin)
    if not User.query.filter_by(email="user@example.com").first():
        user = User(email="user@example.com", name="Regular User", roles="user")
        user.set_password("UserPassw0rd!")
        db.session.add(user)
    db.session.commit()
    print("Database initialized with sample users.")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
