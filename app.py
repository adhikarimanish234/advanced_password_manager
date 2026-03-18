import os
import secrets

from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, session, make_response
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect as sa_inspect, text as sa_text
from cryptography.fernet import Fernet
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import zxcvbn

# ── App setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)

# Secret key from environment
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")

# Database URL:
# - local default: sqlite:///passwords.db
# - online: use DATABASE_URL from hosting platform
database_url = os.environ.get("DATABASE_URL", "sqlite:///passwords.db")

# Some hosts provide postgres://, but SQLAlchemy expects postgresql://
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True

# In production, secure cookies should be True when using HTTPS
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"

db = SQLAlchemy(app)
ph = PasswordHasher()

# ── Fernet key setup ────────────────────────────────────────────────────────
# Online deployment: set FERNET_KEY in environment variables
# Local fallback: store/read from secret.key file
KEY_FILE = "secret.key"
env_fernet_key = os.environ.get("FERNET_KEY")

if env_fernet_key:
    FERNET_KEY = env_fernet_key.encode()
else:
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            FERNET_KEY = f.read()
    else:
        FERNET_KEY = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(FERNET_KEY)

fernet = Fernet(FERNET_KEY)

# ── Default categories ──────────────────────────────────────────────────────
DEFAULT_CATEGORIES = ["General", "Email", "Banking", "Shopping", "Social", "Work"]

# ── In-memory extension tokens ──────────────────────────────────────────────
# Tokens are reset when server restarts.
_ext_tokens = {}  # { token: user_id }

# ── Models ──────────────────────────────────────────────────────────────────
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)

    passwords = db.relationship(
        "StoredPassword",
        backref="owner",
        lazy=True,
        cascade="all, delete-orphan"
    )
    categories = db.relationship(
        "UserCategory",
        backref="owner",
        lazy=True,
        cascade="all, delete-orphan"
    )


class StoredPassword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    website = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), default="General")
    strength_score = db.Column(db.Integer, default=0)
    is_favourite = db.Column(db.Boolean, default=False, nullable=False)


class UserCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(50), nullable=False)


# ── Migration ────────────────────────────────────────────────────────────────
def migrate_database():
    with app.app_context():
        inspector = sa_inspect(db.engine)
        tables = inspector.get_table_names()
        needs_reset = False

        if "master_password" in tables:
            print("⚠️ Old single-user schema detected. Migrating...")
            needs_reset = True

        if "stored_password" in tables:
            cols = [c["name"] for c in inspector.get_columns("stored_password")]
            if "user_id" not in cols:
                needs_reset = True

        if "user" in tables:
            cols = [c["name"] for c in inspector.get_columns("user")]
            if "username" not in cols:
                needs_reset = True

        if needs_reset:
            db.drop_all()
            db.create_all()
            print("✅ Database rebuilt with full schema.")
            return

        db.create_all()

        if "stored_password" in tables:
            cols = [c["name"] for c in inspector.get_columns("stored_password")]
            if "is_favourite" not in cols:
                with db.engine.connect() as conn:
                    conn.execute(sa_text(
                        "ALTER TABLE stored_password "
                        "ADD COLUMN is_favourite BOOLEAN NOT NULL DEFAULT 0"
                    ))
                    conn.commit()
                print("✅ Added is_favourite column.")

        print("✅ Database schema up to date.")


# ── Helpers ─────────────────────────────────────────────────────────────────
def current_user_id():
    """
    Returns logged-in user ID from either:
    - Flask session (web app)
    - X-Ext-Token header (browser extension)
    """
    if session.get("user_id"):
        return session["user_id"]

    token = request.headers.get("X-Ext-Token", "")
    return _ext_tokens.get(token)


def logged_in():
    return current_user_id() is not None


def get_user_by_id(uid):
    try:
        return db.session.get(User, uid)
    except Exception:
        return User.query.get(uid)


def all_categories_for(user_id):
    custom = [c.name for c in UserCategory.query.filter_by(user_id=user_id).all()]
    merged = list(DEFAULT_CATEGORIES)
    for c in custom:
        if c not in merged:
            merged.append(c)
    return merged


# ── Extension CORS ──────────────────────────────────────────────────────────
@app.after_request
def add_extension_cors(response):
    origin = request.headers.get("Origin", "")
    if "extension://" in origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Ext-Token"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response


# ── Page Routes ─────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("login.html")


@app.route("/setup", methods=["GET"])
def setup_page():
    return render_template("setup.html")


@app.route("/setup", methods=["POST"])
def setup():
    uname = request.form.get("username", "").strip()
    pw = request.form.get("masterPassword", "").strip()
    confirm = request.form.get("confirmPassword", "").strip()

    if not uname or len(uname) < 3:
        return render_template(
            "setup.html",
            error="Username must be at least 3 characters."
        )

    if User.query.filter_by(username=uname).first():
        return render_template(
            "setup.html",
            error=f'Username "{uname}" is already taken.'
        )

    if not pw or len(pw) < 8:
        return render_template(
            "setup.html",
            error="Master password must be at least 8 characters.",
            username=uname
        )

    if pw != confirm:
        return render_template(
            "setup.html",
            error="Passwords do not match.",
            username=uname
        )

    try:
        if zxcvbn.zxcvbn(pw)["score"] < 2:
            return render_template(
                "setup.html",
                error="Master password is too weak.",
                username=uname
            )
    except Exception:
        pass

    user = User(username=uname, password_hash=ph.hash(pw))
    db.session.add(user)
    db.session.commit()

    session.permanent = True
    session["user_id"] = user.id
    session["username"] = user.username

    return redirect(url_for("dashboard"))


@app.route("/login", methods=["POST"])
def login():
    uname = request.form.get("username", "").strip()
    pw = request.form.get("masterPassword", "").strip()

    user = User.query.filter_by(username=uname).first()
    if not user:
        return render_template(
            "login.html",
            error=f'No account found for "{uname}". Please set up first.',
            username=uname
        )

    try:
        ph.verify(user.password_hash, pw)
        session.permanent = True
        session["user_id"] = user.id
        session["username"] = user.username
        return redirect(url_for("dashboard"))
    except VerifyMismatchError:
        return render_template(
            "login.html",
            error="Incorrect master password.",
            username=uname
        )


@app.route("/dashboard")
def dashboard():
    if not logged_in():
        return redirect(url_for("index"))
    return render_template("dashboard.html", username=session.get("username"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ── Account deletion ────────────────────────────────────────────────────────
@app.route("/delete-account", methods=["POST"])
def delete_account():
    if not logged_in():
        return redirect(url_for("index"))

    try:
        user = get_user_by_id(current_user_id())
        if user:
            StoredPassword.query.filter_by(user_id=user.id).delete()
            UserCategory.query.filter_by(user_id=user.id).delete()
            db.session.delete(user)
            db.session.commit()
            session.clear()
    except Exception:
        db.session.rollback()

    return redirect(url_for("index"))


@app.route("/delete-account-verify", methods=["POST"])
def delete_account_verify():
    uname = request.form.get("del_username", "").strip()
    pw = request.form.get("del_password", "").strip()

    if not uname or not pw:
        return render_template(
            "login.html",
            error="Please enter credentials to delete your account.",
            show_delete_modal=True,
            del_username=uname
        )

    user = User.query.filter_by(username=uname).first()
    if not user:
        return render_template(
            "login.html",
            error=f'No account found for "{uname}".',
            show_delete_modal=True,
            del_username=uname
        )

    try:
        ph.verify(user.password_hash, pw)
        StoredPassword.query.filter_by(user_id=user.id).delete()
        UserCategory.query.filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()
        session.clear()
        return render_template(
            "login.html",
            success=f'Account "{uname}" permanently deleted.'
        )
    except VerifyMismatchError:
        return render_template(
            "login.html",
            error="Incorrect password. Account NOT deleted.",
            show_delete_modal=True,
            del_username=uname
        )
    except Exception as e:
        db.session.rollback()
        return render_template(
            "login.html",
            error=f"Error: {e}",
            show_delete_modal=True,
            del_username=uname
        )


# ── Info pages ──────────────────────────────────────────────────────────────
@app.route("/features")
def features():
    return render_template("features.html")


@app.route("/security")
def security():
    return render_template("security.html")


@app.route("/about")
def about():
    return render_template("about.html")


# ════════════════════════════════════════════════════════════════════════════
# Browser Extension Auth
# ════════════════════════════════════════════════════════════════════════════
@app.route("/api/ext/login", methods=["POST", "OPTIONS"])
def ext_login():
    if request.method == "OPTIONS":
        return make_response("", 204)

    data = request.get_json(force=True, silent=True) or {}
    uname = data.get("username", "").strip()
    pw = data.get("password", "").strip()

    if not uname or not pw:
        return jsonify({"error": "Username and password are required."}), 400

    user = User.query.filter_by(username=uname).first()
    if not user:
        return jsonify({
            "error": f'No account found for "{uname}". Create one at /setup'
        }), 401

    try:
        ph.verify(user.password_hash, pw)
        token = secrets.token_hex(32)
        _ext_tokens[token] = user.id
        return jsonify({
            "token": token,
            "username": user.username,
            "message": "Login successful"
        })
    except VerifyMismatchError:
        return jsonify({"error": "Incorrect master password."}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ext/logout", methods=["POST", "OPTIONS"])
def ext_logout():
    if request.method == "OPTIONS":
        return make_response("", 204)

    token = request.headers.get("X-Ext-Token", "")
    _ext_tokens.pop(token, None)
    return jsonify({"message": "Logged out successfully."})


@app.route("/api/ext/status", methods=["GET", "OPTIONS"])
def ext_status():
    if request.method == "OPTIONS":
        return make_response("", 204)

    uid = current_user_id()
    if not uid:
        return jsonify({"logged_in": False}), 401

    user = get_user_by_id(uid)
    return jsonify({
        "logged_in": True,
        "username": user.username if user else "Unknown"
    })


# ════════════════════════════════════════════════════════════════════════════
# Password API
# ════════════════════════════════════════════════════════════════════════════
@app.route("/api/strength/check", methods=["POST", "OPTIONS"])
def check_strength():
    if request.method == "OPTIONS":
        return make_response("", 204)

    try:
        data = request.get_json(force=True, silent=True) or {}
        password = data.get("password", "")

        if not password:
            return jsonify({"error": "Password required"}), 400

        result = zxcvbn.zxcvbn(password)
        score = result["score"]
        feedback = (result["feedback"]["suggestions"] or ["Looking good!"])[0]

        return jsonify({
            "score": score,
            "strength": ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"][score],
            "feedback": feedback,
            "crack_time": result["crack_times_display"]["offline_fast_hashing_1e10_per_second"],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/passwords/store", methods=["POST", "OPTIONS"])
def store_password():
    if request.method == "OPTIONS":
        return make_response("", 204)

    if not logged_in():
        return jsonify({"error": "Unauthorised"}), 401

    try:
        data = request.get_json(force=True, silent=True) or {}
        website = data.get("website", "").strip()
        uname = data.get("username", "").strip()
        password = data.get("password", "").strip()
        category = (data.get("category", "General") or "General").strip()

        if not website or not uname or not password:
            return jsonify({
                "error": "Website, username and password are all required."
            }), 400

        result = zxcvbn.zxcvbn(password)
        encrypted = fernet.encrypt(password.encode()).decode()

        entry = StoredPassword(
            user_id=current_user_id(),
            website=website,
            username=uname,
            encrypted_password=encrypted,
            category=category,
            strength_score=result["score"],
            is_favourite=False
        )

        db.session.add(entry)
        db.session.commit()

        return jsonify({
            "message": "Password saved!",
            "id": entry.id,
            "strength_score": result["score"]
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route("/api/passwords/update/<int:entry_id>", methods=["PUT", "OPTIONS"])
def update_password(entry_id):
    if request.method == "OPTIONS":
        return make_response("", 204)

    if not logged_in():
        return jsonify({"error": "Unauthorised"}), 401

    try:
        entry = StoredPassword.query.filter_by(
            id=entry_id,
            user_id=current_user_id()
        ).first()

        if not entry:
            return jsonify({"error": "Entry not found."}), 404

        data = request.get_json(force=True, silent=True) or {}

        entry.website = data.get("website", entry.website).strip()
        entry.username = data.get("username", entry.username).strip()
        entry.category = (data.get("category", entry.category) or "General").strip()

        password = data.get("password", "").strip()
        if password:
            result = zxcvbn.zxcvbn(password)
            entry.encrypted_password = fernet.encrypt(password.encode()).decode()
            entry.strength_score = result["score"]

        db.session.commit()
        return jsonify({
            "message": "Entry updated successfully!",
            "id": entry.id
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route("/api/passwords/list", methods=["GET", "OPTIONS"])
def list_passwords():
    if request.method == "OPTIONS":
        return make_response("", 204)

    if not logged_in():
        return jsonify({"error": "Unauthorised"}), 401

    try:
        entries = (
            StoredPassword.query
            .filter_by(user_id=current_user_id())
            .order_by(StoredPassword.id.desc())
            .all()
        )

        return jsonify([
            {
                "id": e.id,
                "website": e.website,
                "username": e.username,
                "category": e.category or "General",
                "strength_score": e.strength_score,
                "is_favourite": bool(e.is_favourite),
            }
            for e in entries
        ])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/passwords/decrypt/<int:entry_id>", methods=["GET", "OPTIONS"])
def decrypt_password(entry_id):
    if request.method == "OPTIONS":
        return make_response("", 204)

    if not logged_in():
        return jsonify({"error": "Unauthorised"}), 401

    try:
        entry = StoredPassword.query.filter_by(
            id=entry_id,
            user_id=current_user_id()
        ).first()

        if not entry:
            return jsonify({"error": "Entry not found."}), 404

        decrypted = fernet.decrypt(entry.encrypted_password.encode()).decode()
        result = zxcvbn.zxcvbn(decrypted)

        return jsonify({
            "id": entry.id,
            "website": entry.website,
            "username": entry.username,
            "password": decrypted,
            "category": entry.category or "General",
            "strength_score": entry.strength_score,
            "is_favourite": bool(entry.is_favourite),
            "strength_label": ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"][entry.strength_score],
            "crack_time": result["crack_times_display"]["offline_fast_hashing_1e10_per_second"],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/passwords/favourite/<int:entry_id>", methods=["POST", "OPTIONS"])
def toggle_favourite(entry_id):
    if request.method == "OPTIONS":
        return make_response("", 204)

    if not logged_in():
        return jsonify({"error": "Unauthorised"}), 401

    try:
        entry = StoredPassword.query.filter_by(
            id=entry_id,
            user_id=current_user_id()
        ).first()

        if not entry:
            return jsonify({"error": "Entry not found."}), 404

        entry.is_favourite = not entry.is_favourite
        db.session.commit()

        return jsonify({
            "is_favourite": entry.is_favourite,
            "message": "Added to favourites!" if entry.is_favourite else "Removed from favourites."
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route("/api/passwords/delete/<int:entry_id>", methods=["DELETE", "OPTIONS"])
def delete_password(entry_id):
    if request.method == "OPTIONS":
        return make_response("", 204)

    if not logged_in():
        return jsonify({"error": "Unauthorised"}), 401

    try:
        entry = StoredPassword.query.filter_by(
            id=entry_id,
            user_id=current_user_id()
        ).first()

        if not entry:
            return jsonify({"error": "Not found."}), 404

        db.session.delete(entry)
        db.session.commit()

        return jsonify({"message": "Deleted."})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# ── Category API ────────────────────────────────────────────────────────────
@app.route("/api/categories/list", methods=["GET", "OPTIONS"])
def list_categories():
    if request.method == "OPTIONS":
        return make_response("", 204)

    if not logged_in():
        return jsonify({"error": "Unauthorised"}), 401

    try:
        custom = UserCategory.query.filter_by(user_id=current_user_id()).all()
        return jsonify({
            "default": DEFAULT_CATEGORIES,
            "custom": [{"id": c.id, "name": c.name} for c in custom],
            "all": all_categories_for(current_user_id()),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/categories/add", methods=["POST", "OPTIONS"])
def add_category():
    if request.method == "OPTIONS":
        return make_response("", 204)

    if not logged_in():
        return jsonify({"error": "Unauthorised"}), 401

    try:
        data = request.get_json(force=True, silent=True) or {}
        name = (data.get("name") or "").strip()

        if not name or len(name) < 2:
            return jsonify({"error": "Category name must be at least 2 characters."}), 400

        if len(name) > 30:
            return jsonify({"error": "Category name too long (max 30 chars)."}), 400

        all_cats = all_categories_for(current_user_id())
        if name.lower() in [c.lower() for c in all_cats]:
            return jsonify({"error": f'Category "{name}" already exists.'}), 409

        cat = UserCategory(user_id=current_user_id(), name=name)
        db.session.add(cat)
        db.session.commit()

        return jsonify({
            "message": f'Category "{name}" created!',
            "id": cat.id,
            "name": cat.name
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route("/api/categories/delete/<int:cat_id>", methods=["DELETE", "OPTIONS"])
def delete_category(cat_id):
    if request.method == "OPTIONS":
        return make_response("", 204)

    if not logged_in():
        return jsonify({"error": "Unauthorised"}), 401

    try:
        cat = UserCategory.query.filter_by(
            id=cat_id,
            user_id=current_user_id()
        ).first()

        if not cat:
            return jsonify({"error": "Category not found."}), 404

        StoredPassword.query.filter_by(
            user_id=current_user_id(),
            category=cat.name
        ).update({"category": "General"})

        db.session.delete(cat)
        db.session.commit()

        return jsonify({
            "message": f'Category "{cat.name}" deleted. Entries moved to General.'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# ── Health check ────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


# ── Local run only ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    migrate_database()
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)