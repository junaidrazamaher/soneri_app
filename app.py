import os
from datetime import datetime
from bson.objectid import ObjectId

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SelectField, DecimalField, DateField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Email, Length, Optional, Regexp, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from dotenv import load_dotenv

# Load env
load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change_this_in_production")
# Cookie security options (set True in production with https)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config['WTF_CSRF_ENABLED'] = False


csrf = CSRFProtect(app)

# MongoDB connection (Atlas URI from .env)
MONGO_URI = os.getenv("MONGO_URI") or "mongodb://localhost:27017/"
client = MongoClient(MONGO_URI)
db = client.get_database("soneri_app")  # db name
users_col = db["users"]
records_col = db["records"]
audit_col = db["audit_logs"]

# ------------------------------
# Forms (WTForms) - detailed banking-grade fields
# ------------------------------
class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = StringField("Password", validators=[DataRequired(), Length(min=8)])

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = StringField("Password", validators=[DataRequired()])

class RecordForm(FlaskForm):
    # Personal Info
    full_name = StringField("Full Name", validators=[DataRequired(), Length(max=150)])
    date_of_birth = DateField("Date of Birth (YYYY-MM-DD)", validators=[Optional()], format="%Y-%m-%d")
    national_id = StringField("National ID / CNIC", validators=[Optional(), Regexp(r'^[0-9\-]+$', message="Invalid ID")])
    phone = StringField("Phone", validators=[Optional(), Length(max=30)])
    email = StringField("Email", validators=[Optional(), Email()])
    address = TextAreaField("Address", validators=[Optional(), Length(max=500)])

    # Account Info
    account_no = StringField("Account Number", validators=[DataRequired(), Length(max=50)])
    account_type = SelectField("Account Type", choices=[("savings","Savings"),("current","Current"),("fixed","Fixed Deposit")], validators=[DataRequired()])
    branch_code = StringField("Branch Code", validators=[Optional(), Length(max=20)])
    currency = SelectField("Currency", choices=[("PKR","PKR"),("USD","USD"),("EUR","EUR")], validators=[DataRequired()])
    opening_balance = DecimalField("Opening Balance", validators=[Optional(), NumberRange(min=0)], places=2, default=0)

    # Security / Limits / Flags
    transaction_limit_daily = DecimalField("Daily Transaction Limit", validators=[Optional(), NumberRange(min=0)], places=2, default=0)
    kyc_status = SelectField("KYC Status", choices=[("pending","Pending"),("verified","Verified"),("rejected","Rejected")], validators=[DataRequired()])
    risk_score = IntegerField("Risk Score (0-100)", validators=[Optional(), NumberRange(min=0, max=100)], default=10)

    # Metadata
    status = SelectField("Account Status", choices=[("active","Active"),("suspended","Suspended"),("closed","Closed")], validators=[DataRequired()])
    notes = TextAreaField("Notes", validators=[Optional(), Length(max=2000)])

# ------------------------------
# Auth helpers
# ------------------------------
def create_user(username, email, raw_password):
    hashed = generate_password_hash(raw_password)
    user = {"username": username, "email": email, "password": hashed, "created_at": datetime.utcnow()}
    return users_col.insert_one(user).inserted_id

def find_user_by_email(email):
    return users_col.find_one({"email": email})

# ------------------------------
# Audit helper
# ------------------------------
def audit(action, actor, target_id=None, details=None):
    audit_col.insert_one({
        "action": action,
        "actor": actor,
        "target_id": str(target_id) if target_id else None,
        "details": details,
        "ts": datetime.utcnow()
    })

# ------------------------------
# Routes: Auth
# ------------------------------
@app.route("/register", methods=["GET","POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if find_user_by_email(form.email.data):
            flash("Email already registered.", "danger")
            return redirect(url_for("register"))
        uid = create_user(form.username.data, form.email.data, form.password.data)
        audit("user.register", form.email.data, target_id=uid)
        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = find_user_by_email(form.email.data)
        if user and check_password_hash(user["password"], form.password.data):
            # set session
            session["user_id"] = str(user["_id"])
            session["username"] = user["username"]
            session.permanent = True
            audit("user.login", session["username"])
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
def logout():
    actor = session.get("username")
    session.clear()
    if actor:
        audit("user.logout", actor)
    flash("Logged out.", "info")
    return redirect(url_for("login"))

# ------------------------------
# Routes: CRUD for Records
# ------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    # fetch all records (careful with very large collections -> add pagination later)
    records = list(records_col.find().sort("created_at", -1))
    return render_template("dashboard.html", records=records)

@app.route("/records/add", methods=["GET","POST"])
def add_record():
    if "user_id" not in session:
        return redirect(url_for("login"))
    form = RecordForm()
    if form.validate_on_submit():
        rec = {
            "full_name": form.full_name.data,
            "date_of_birth": form.date_of_birth.data.isoformat() if form.date_of_birth.data else None,
            "national_id": form.national_id.data,
            "phone": form.phone.data,
            "email": form.email.data,
            "address": form.address.data,
            "account_no": form.account_no.data,
            "account_type": form.account_type.data,
            "branch_code": form.branch_code.data,
            "currency": form.currency.data,
            "opening_balance": float(form.opening_balance.data or 0),
            "transaction_limit_daily": float(form.transaction_limit_daily.data or 0),
            "kyc_status": form.kyc_status.data,
            "risk_score": int(form.risk_score.data or 0),
            "status": form.status.data,
            "notes": form.notes.data,
            "created_by": session.get("username"),
            "created_at": datetime.utcnow(),
            "updated_at": None
        }
        res = records_col.insert_one(rec)
        audit("record.create", session.get("username"), target_id=res.inserted_id, details={"account_no": rec["account_no"], "full_name": rec["full_name"]})
        flash("Record created successfully.", "success")
        return redirect(url_for("dashboard"))
    return render_template("add_record.html", form=form)

@app.route("/records/<rid>/view")
def view_record(rid):
    if "user_id" not in session:
        return redirect(url_for("login"))
    rec = records_col.find_one({"_id": ObjectId(rid)})
    if not rec:
        flash("Record not found.", "danger")
        return redirect(url_for("dashboard"))
    return render_template("view_record.html", r=rec)

@app.route("/records/<rid>/edit", methods=["GET","POST"])
def edit_record(rid):
    if "user_id" not in session:
        return redirect(url_for("login"))
    rec = records_col.find_one({"_id": ObjectId(rid)})
    if not rec:
        flash("Record not found.", "danger")
        return redirect(url_for("dashboard"))
    form = RecordForm(data={
        "full_name": rec.get("full_name"),
        "date_of_birth": rec.get("date_of_birth"),
        "national_id": rec.get("national_id"),
        "phone": rec.get("phone"),
        "email": rec.get("email"),
        "address": rec.get("address"),
        "account_no": rec.get("account_no"),
        "account_type": rec.get("account_type"),
        "branch_code": rec.get("branch_code"),
        "currency": rec.get("currency"),
        "opening_balance": rec.get("opening_balance"),
        "transaction_limit_daily": rec.get("transaction_limit_daily"),
        "kyc_status": rec.get("kyc_status"),
        "risk_score": rec.get("risk_score"),
        "status": rec.get("status"),
        "notes": rec.get("notes")
    })
    # Note: date_of_birth stored as ISO string earlier; WTForms DateField expects date object — for simplicity we'll not pre-populate DOB field here if string
    if form.validate_on_submit():
        update = {
            "full_name": form.full_name.data,
            "date_of_birth": form.date_of_birth.data.isoformat() if form.date_of_birth.data else None,
            "national_id": form.national_id.data,
            "phone": form.phone.data,
            "email": form.email.data,
            "address": form.address.data,
            "account_no": form.account_no.data,
            "account_type": form.account_type.data,
            "branch_code": form.branch_code.data,
            "currency": form.currency.data,
            "opening_balance": float(form.opening_balance.data or 0),
            "transaction_limit_daily": float(form.transaction_limit_daily.data or 0),
            "kyc_status": form.kyc_status.data,
            "risk_score": int(form.risk_score.data or 0),
            "status": form.status.data,
            "notes": form.notes.data,
            "updated_at": datetime.utcnow()
        }
        records_col.update_one({"_id": ObjectId(rid)}, {"$set": update})
        audit("record.update", session.get("username"), target_id=rid, details={"account_no": update["account_no"]})
        flash("Record updated.", "success")
        return redirect(url_for("dashboard"))
    return render_template("edit_record.html", form=form, rid=rid, rec=rec)

@app.route("/records/<rid>/delete", methods=["POST"])
def delete_record(rid):
    if "user_id" not in session:
        return redirect(url_for("login"))
    rec = records_col.find_one({"_id": ObjectId(rid)})
    if not rec:
        flash("Record not found.", "danger")
    else:
        records_col.delete_one({"_id": ObjectId(rid)})
        audit("record.delete", session.get("username"), target_id=rid, details={"account_no": rec.get("account_no")})
        flash("Record deleted.", "info")
    return redirect(url_for("dashboard"))

# API endpoint for DataTables (optional) - returns JSON list (safe)
@app.route("/api/records")
def api_records():
    if "user_id" not in session:
        return jsonify({"error": "unauthorized"}), 401
    docs = []
    for r in records_col.find().sort("created_at", -1):
        docs.append({
            "_id": str(r["_id"]),
            "full_name": r.get("full_name"),
            "account_no": r.get("account_no"),
            "email": r.get("email"),
            "phone": r.get("phone"),
            "account_type": r.get("account_type"),
            "status": r.get("status")
        })
    return jsonify({"data": docs})

if __name__ == "__main__":
    app.run(debug=True, port=5000)
