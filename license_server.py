# license_server.py
import os, datetime, uuid, hashlib, base64, hmac, json
from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
import jwt

# ---------------- CONFIG ----------------
JWT_SECRET = os.getenv("JWT_SECRET", "replace-with-secure-jwt-secret")
JWT_ALG = "HS256"
TRIAL_DAYS = int(os.getenv("TRIAL_DAYS", "2"))
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "replace-admin-key")  # protect this
OFFLINE_GRACE_DAYS = int(os.getenv("OFFLINE_GRACE_DAYS", "5"))
DB_URI = os.getenv("DATABASE_URL", "sqlite:///licenses.db")
PORT = int(os.getenv("PORT", "5000"))

# Fix for Render's PostgreSQL URL format
if DB_URI and DB_URI.startswith("postgres://"):
    DB_URI = DB_URI.replace("postgres://", "postgresql://", 1)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ---------------- MODELS ----------------
class License(db.Model):   
    __tablename__ = 'license'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String, unique=True, nullable=False)   # paid license key or SKU
    kind = db.Column(db.String, default="paid")               # 'paid' or 'trial'
    expiry = db.Column(db.Date, nullable=True)
    activation_limit = db.Column(db.Integer, default=1)
    activations = db.Column(db.Integer, default=0)
    revoked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Activation(db.Model):
    __tablename__ = 'activation'
    id = db.Column(db.Integer, primary_key=True)
    license_id = db.Column(db.Integer, db.ForeignKey("license.id"), nullable=False)
    hwid = db.Column(db.String, nullable=False)
    token = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class TrialKey(db.Model):
    __tablename__ = 'trial_key'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String, unique=True, nullable=False)  # UUID per installer
    used = db.Column(db.Boolean, default=False)
    activated_hwid = db.Column(db.String, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    used_at = db.Column(db.DateTime, nullable=True)

# ---------------- HELPERS ----------------
def gen_key(nbytes=9):
    return base64.urlsafe_b64encode(os.urandom(nbytes)).decode().rstrip("=")

def hwid_fingerprint(hwid_raw: str) -> str:
    return hashlib.sha256(hwid_raw.encode("utf-8")).hexdigest()

def sign_activation(license_key: str, hwid: str, expiry: datetime.date):
    payload = {
        "lic": license_key,
        "hw": hwid,
        "exp": int(datetime.datetime(expiry.year, expiry.month, expiry.day, 23, 59, 59).timestamp()),
        "iat": int(datetime.datetime.utcnow().timestamp())
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
    return token

def validate_jwt(token):
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return True, data
    except Exception as e:
        return False, str(e)

def require_admin():
    key = request.headers.get("X-API-KEY")
    if not key or key != ADMIN_API_KEY:
        abort(401)


def init_database():
    """Initialize database tables"""
    try:
        print("Initializing database...")
        db.create_all()
        print("Database tables created successfully!")
        
        # Verify tables exist
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        print(f"Tables in database: {tables}")
        
        if 'trial_key' not in tables:
            print("WARNING: trial_key table not found!")
            # Force create the table
            TrialKey.__table__.create(db.engine, checkfirst=True)
            print("Created trial_key table manually")
            
        if 'license' not in tables:
            print("WARNING: license table not found!")
            License.__table__.create(db.engine, checkfirst=True)
            print("Created license table manually")
            
        if 'activation' not in tables:
            print("WARNING: activation table not found!")
            Activation.__table__.create(db.engine, checkfirst=True)
            print("Created activation table manually")
            
    except Exception as e:
        print(f"Database initialization error: {e}")
        raise


# ---------------- ADMIN ENDPOINTS ----------------
@app.route("/admin/create_paid", methods=["POST"])
def admin_create_paid():
    require_admin()
    body = request.get_json() or {}
    days = int(body.get("days", 365))
    limit = int(body.get("limit", 1))
    key = gen_key()
    expiry = (datetime.date.today() + datetime.timedelta(days=days))
    lic = License(key=key, kind="paid", expiry=expiry, activation_limit=limit)
    db.session.add(lic); db.session.commit()
    return jsonify({"key": key, "expiry": expiry.isoformat(), "limit": limit})

@app.route("/admin/create_trial", methods=["POST"])
def admin_create_trial():
    require_admin()
    # generate a fresh trial key for embedding into a single installer
    key = str(uuid.uuid4())
    tk = TrialKey(key=key)
    db.session.add(tk); db.session.commit()
    expiry = (datetime.date.today() + datetime.timedelta(days=TRIAL_DAYS))
    return jsonify({"key": key, "expiry": expiry.isoformat()})

@app.route("/admin/revoke", methods=["POST"])
def admin_revoke():
    require_admin()
    body = request.get_json() or {}
    key = body.get("key")
    lic = License.query.filter_by(key=key).first()
    if not lic:
        return jsonify({"error":"not found"}), 404
    lic.revoked = True
    db.session.commit()
    return jsonify({"ok": True})

# ---------------- CLIENT ENDPOINTS ----------------
@app.route("/activate", methods=["POST"])
def activate():
    """
    Request body: {"key": "<license_or_trial_key>", "hwid": "<raw_hwid>"}
    """
    data = request.get_json() or {}
    key = data.get("key")
    raw_hwid = data.get("hwid", "")
    if not key:
        return jsonify({"error":"missing key"}), 400
    hwid = hwid_fingerprint(raw_hwid)

    # 1) paid license flow?
    lic = License.query.filter_by(key=key).first()
    if lic:
        if lic.revoked:
            return jsonify({"error":"revoked"}), 403
        act = Activation.query.filter_by(license_id=lic.id, hwid=hwid).first()
        if act:
            act.last_seen = datetime.datetime.utcnow()
        else:
            if lic.activations >= lic.activation_limit:
                return jsonify({"error":"activation_limit_reached"}), 403
            act = Activation(license_id=lic.id, hwid=hwid)
            lic.activations += 1
            db.session.add(act)
        expiry = lic.expiry or (datetime.date.today() + datetime.timedelta(days=TRIAL_DAYS))
        token = sign_activation(lic.key, hwid, expiry)
        act.token = token
        db.session.commit()
        return jsonify({"token": token, "expiry": expiry.isoformat(), "kind": lic.kind, "offline_grace_days": OFFLINE_GRACE_DAYS})

    # 2) trial key flow
    tk = TrialKey.query.filter_by(key=key).first()
    if not tk:
        return jsonify({"error":"invalid_key"}), 404
    if tk.used:
        return jsonify({"error":"trial_already_used"}), 403
    # consume trial key
    tk.used = True
    tk.activated_hwid = hwid
    tk.used_at = datetime.datetime.utcnow()
    expiry = datetime.date.today() + datetime.timedelta(days=TRIAL_DAYS)
    token = sign_activation(key, hwid, expiry)
    # create an associated License record for auditing (optional)
    lic = License(key=key, kind="trial", expiry=expiry, activation_limit=1, activations=1)
    db.session.add(lic)
    act = Activation(license_id=lic.id, hwid=hwid, token=token)
    db.session.add(act)
    db.session.commit()
    return jsonify({"token": token, "expiry": expiry.isoformat(), "kind": "trial", "offline_grace_days": OFFLINE_GRACE_DAYS})

@app.route("/validate", methods=["POST"])
def validate():
    data = request.json
    trial_key = data.get("trial_key")
    hwid = data.get("hwid")

    tk = TrialKey.query.filter_by(key=trial_key).first()
    if not tk:
        return jsonify({"valid": False}), 401

    if tk.used and tk.activated_hwid != hwid:
        return jsonify({"valid": False}), 401

    # Bind key to hwid first time
    if not tk.activated_hwid:
        tk.activated_hwid = hwid
        tk.used = True
        db.session.commit()

    # Expiry check
    if tk.used_at and datetime.utcnow() > tk.used_at + datetime.timedelta(days=2):
        return jsonify({"valid": False}), 401

    return jsonify({"valid": True})

@app.route("/admin/init_db", methods=["POST"])
def admin_init_db():
    """Force database initialization"""
    require_admin()
    try:
        init_database()
        return jsonify({"message": "Database initialized successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json() or {}
    token = data.get("token")
    raw_hwid = data.get("hwid","")
    if not token:
        return jsonify({"error":"missing token"}), 400
    ok, payload_or_err = validate_jwt(token)
    if not ok:
        return jsonify({"error":"invalid_token", "reason": payload_or_err}), 403
    hwid = hwid_fingerprint(raw_hwid)
    # check license record
    key = payload_or_err.get("lic")
    lic = License.query.filter_by(key=key).first()
    if not lic or lic.revoked:
        return jsonify({"error":"invalid_or_revoked"}), 403
    if payload_or_err.get("hw") != hwid:
        return jsonify({"error":"hwid_mismatch"}), 403
    exp_ts = payload_or_err.get("exp")
    if exp_ts and datetime.datetime.utcfromtimestamp(exp_ts).date() < datetime.date.today():
        return jsonify({"error":"expired"}), 403
    # update activation last seen if present
    act = Activation.query.filter_by(license_id=lic.id, hwid=hwid).first()
    if act:
        act.last_seen = datetime.datetime.utcnow()
        db.session.commit()
    return jsonify({"ok": True, "expiry": lic.expiry.isoformat() if lic.expiry else None, "kind": lic.kind})

@app.route("/deactivate", methods=["POST"])
def deactivate():
    data = request.get_json() or {}
    token = data.get("token")
    raw_hwid = data.get("hwid","")
    ok, payload_or_err = validate_jwt(token)
    if not ok:
        return jsonify({"error":"invalid_token"}), 403
    key = payload_or_err.get("lic")
    hwid = hwid_fingerprint(raw_hwid)
    lic = License.query.filter_by(key=key).first()
    act = Activation.query.filter_by(license_id=lic.id, hwid=hwid).first()
    if act:
        db.session.delete(act)
        lic.activations = max(0, lic.activations - 1)
        db.session.commit()
    return jsonify({"ok": True})

# # ---------------- INIT ----------------
# if __name__ == "__main__":
#     with app.app_context():
#         db.create_all()
#     app.run(host="0.0.0.0", port=PORT)

# ---------------- INIT ----------------
def create_app():
    """Application factory"""
    with app.app_context():
        init_database()
    return app

if __name__ == "__main__":
    with app.app_context():
        init_database()
    app.run(host="0.0.0.0", port=PORT)
else:
    # For production WSGI servers
    with app.app_context():
        init_database()
