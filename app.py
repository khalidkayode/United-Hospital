"""United Hospital - Electronic Patient Record Management System (EPR).

A small Flask + SQLite web application implementing the modules described in the
project write-up: authentication, patient registration, patient records,
consultation & diagnosis, prescriptions, laboratory, appointments, search,
reporting, user administration and audit logging.
"""
import os
import re
import secrets
import sqlite3
from datetime import date, datetime, timedelta
from functools import wraps

import click
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)

ADMIN, DOCTOR, LAB = "Administrator", "Doctor", "Laboratory"
ROLES = [ADMIN, DOCTOR, LAB]
BLOOD_GROUPS = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]
COMMON_TESTS = [
    "Malaria Parasite (MP)", "Full Blood Count (CBC)", "Lipid Panel", "HbA1c",
    "Fasting Blood Sugar", "Widal Test", "Urinalysis", "Liver Function Test",
    "Hepatitis B Surface Antigen", "Genotype",
]
FREQUENCIES = ["Once daily", "Twice daily (BD)", "Three times daily (TDS)",
               "Four times daily (QDS)", "At night", "As needed"]
APPOINTMENT_SLOTS = [f"{h:02d}:{m:02d}" for h in range(8, 17) for m in (0, 30)
                     if not (h == 16 and m == 30)]
# Nigerian mobile numbers: 0803 214 5670 or +234 803 214 5670
PHONE_RE = re.compile(r"^0[789][01]\d{8}$")

app = Flask(__name__)
app.config["DATABASE"] = os.environ.get(
    "EPR_DATABASE", os.path.join(INSTANCE_DIR, "united_epr.db"))
app.config["HOSPITAL_NAME"] = os.environ.get("HOSPITAL_NAME", "United Hospital")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def _load_secret_key():
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(INSTANCE_DIR, "secret_key")
    if not os.path.exists(path):
        with open(path, "w") as fh:
            fh.write(secrets.token_hex(32))
    with open(path) as fh:
        return fh.read().strip()


app.secret_key = _load_secret_key()


# --------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rows = cur.fetchall()
    cur.close()
    if one:
        return rows[0] if rows else None
    return rows


def execute(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur.lastrowid


def hash_password(password):
    """PBKDF2-SHA256 works on every Python build (scrypt is missing on some, e.g. macOS system Python)."""
    return generate_password_hash(password, method="pbkdf2:sha256")


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today():
    return date.today().isoformat()


def init_db():
    """Create all tables and the three system roles."""
    with app.app_context():
        db = get_db()
        with open(os.path.join(BASE_DIR, "schema.sql")) as fh:
            db.executescript(fh.read())
        for role in ROLES:
            db.execute("INSERT INTO roles(role_name) VALUES (?)", (role,))
        db.commit()


def log_action(action, details="", patient_id=None, user_id=None):
    uid = user_id if user_id is not None else session.get("user_id")
    execute("INSERT INTO audit_log(user_id, patient_id, action, details, created_at) "
            "VALUES (?,?,?,?,?)", (uid, patient_id, action, details, now()))


# --------------------------------------------------------------------------
# Template filters
# --------------------------------------------------------------------------
@app.template_filter("rx")
def rx_code(i):
    return f"RX{100000 + int(i)}"


@app.template_filter("tcode")
def test_code(i):
    return f"T{12000 + int(i)}"


@app.template_filter("age")
def age_filter(dob):
    d = date.fromisoformat(dob)
    t = date.today()
    return t.year - d.year - ((t.month, t.day) < (d.month, d.day))


@app.template_filter("fdate")
def fdate(value, fmt="%d %b %Y"):
    if not value:
        return ""
    try:
        dt = datetime.strptime(value[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        dt = datetime.strptime(value[:10], "%Y-%m-%d")
    return dt.strftime(fmt)


@app.template_filter("phone")
def fmt_phone(value):
    v = value or ""
    return f"{v[:4]} {v[4:7]} {v[7:]}" if len(v) == 11 else v


@app.template_filter("initials")
def initials(name):
    parts = [p for p in re.sub(r"^Dr\.?\s+", "", name or "").split() if p]
    return "".join(p[0] for p in parts[:2]).upper()


@app.context_processor
def inject_globals():
    def csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(16)
        return session["csrf_token"]
    return {"csrf_token": csrf_token, "hospital": app.config["HOSPITAL_NAME"],
            "ADMIN": ADMIN, "DOCTOR": DOCTOR, "LAB": LAB,
            "current_date": date.today().strftime("%a, %d %b %Y")}


# --------------------------------------------------------------------------
# Security: CSRF, authentication, role-based access control
# --------------------------------------------------------------------------
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get("csrf_token")
        if not token or token != request.form.get("csrf_token"):
            abort(400)


@app.before_request
def load_user():
    g.user = None
    uid = session.get("user_id")
    if uid:
        user = query("SELECT u.*, r.role_name FROM users u JOIN roles r "
                     "ON r.role_id = u.role_id WHERE u.user_id = ?", (uid,), one=True)
        if user and user["status"] == "active":
            g.user = user
        else:
            session.pop("user_id", None)


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*a, **kw):
            if g.user is None:
                return redirect(url_for("login", next=request.path))
            if g.user["role_name"] not in roles:
                log_action("Access denied", f"{request.method} {request.path}")
                abort(403)
            return view(*a, **kw)
        return wrapped
    return decorator


@app.errorhandler(400)
def bad_request(_e):
    return render_template("error.html", code=400, title="Invalid request",
                           message="The form expired or is invalid. Please go back and try again."), 400


@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403, title="Access denied",
                           message="Your role does not have permission to open this page."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, title="Page not found",
                           message="The page or record you asked for does not exist."), 404


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------
def normalize_phone(raw):
    """Return an 11-digit local Nigerian number (0803...) or None if invalid."""
    digits = re.sub(r"[\s\-()]", "", raw or "")
    if digits.startswith("+234"):
        digits = "0" + digits[4:]
    elif digits.startswith("234") and len(digits) == 13:
        digits = "0" + digits[3:]
    return digits if PHONE_RE.match(digits) else None


def safe_next(target):
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return None


def next_free_slot(doctor_id, day, start_time):
    taken = {r["appointment_time"] for r in query(
        "SELECT appointment_time FROM appointments WHERE doctor_id=? AND appointment_date=? "
        "AND status != 'Cancelled'", (doctor_id, day))}
    later = [s for s in APPOINTMENT_SLOTS if s > start_time and s not in taken]
    return later[0] if later else None


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "")
        user = query("SELECT u.*, r.role_name FROM users u JOIN roles r ON r.role_id=u.role_id "
                     "WHERE lower(u.username)=?", (username,), one=True)
        ok = (user is not None and user["status"] == "active"
              and check_password_hash(user["password_hash"], password)
              and (not role or role == user["role_name"]))
        if ok:
            session.clear()
            session["user_id"] = user["user_id"]
            session["csrf_token"] = secrets.token_hex(16)
            log_action("Login", f"{user['full_name']} signed in", user_id=user["user_id"])
            return redirect(safe_next(request.args.get("next")) or url_for("dashboard"))
        log_action("Failed login", f"Username: {username[:40]}", user_id=None)
        error = "Invalid username, password or role. Please try again."
    return render_template("login.html", error=error, roles=ROLES)


@app.route("/logout", methods=["POST"])
def logout():
    if g.user:
        log_action("Logout", f"{g.user['full_name']} signed out")
    session.clear()
    flash("You have been signed out securely.", "info")
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------
@app.route("/")
@login_required
def dashboard():
    t = today()
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    month_start = date.today().replace(day=1).isoformat()
    stats = {
        "patients": query("SELECT COUNT(*) c FROM patients", one=True)["c"],
        "new_month": query("SELECT COUNT(*) c FROM patients WHERE created_at >= ?",
                           (month_start,), one=True)["c"],
        "consult_today": query("SELECT COUNT(*) c FROM consultations WHERE substr(consultation_date,1,10)=?",
                               (t,), one=True)["c"],
        "consult_yday": query("SELECT COUNT(*) c FROM consultations WHERE substr(consultation_date,1,10)=?",
                              (yesterday,), one=True)["c"],
        "pending_lab": query("SELECT COUNT(*) c FROM laboratory_requests WHERE status='Pending'",
                             one=True)["c"],
        "rx_total": query("SELECT COUNT(*) c FROM prescriptions", one=True)["c"],
        "rx_pending": query("SELECT COUNT(*) c FROM prescriptions WHERE status='Pending'", one=True)["c"],
        "appts_today": query("SELECT COUNT(*) c FROM appointments WHERE appointment_date=? "
                             "AND status='Scheduled'", (t,), one=True)["c"],
    }
    recent = query(
        "SELECT a.*, p.first_name || ' ' || p.last_name AS patient_name, p.patient_number, "
        "u.full_name AS staff_name FROM audit_log a "
        "JOIN patients p ON p.patient_id = a.patient_id "
        "LEFT JOIN users u ON u.user_id = a.user_id "
        "WHERE a.action != 'Viewed patient record' ORDER BY a.created_at DESC, a.log_id DESC LIMIT 6")
    return render_template("dashboard.html", stats=stats, recent=recent)


# --------------------------------------------------------------------------
# Patients: search, registration, record
# --------------------------------------------------------------------------
@app.route("/patients")
@login_required
def patients():
    q = request.args.get("q", "").strip()
    try:
        page = max(int(request.args.get("page", 1)), 1)
    except ValueError:
        page = 1
    per_page = 10
    where, args = "", []
    if q:
        like = f"%{q}%"
        phone_digits = re.sub(r"[\s\-]", "", q)
        phone_like = "%" + phone_digits + "%"
        where = ("WHERE first_name LIKE ? OR last_name LIKE ? OR (first_name || ' ' || last_name) LIKE ? "
                 "OR patient_number LIKE ? OR matric_staff_id LIKE ? OR phone LIKE ?")
        args = [like, like, like, like, like, phone_like]
    total = query(f"SELECT COUNT(*) c FROM patients {where}", args, one=True)["c"]
    rows = query(
        f"SELECT p.*, (SELECT MAX(substr(consultation_date,1,10)) FROM consultations c "
        f"WHERE c.patient_id = p.patient_id) AS last_visit FROM patients p {where} "
        f"ORDER BY p.patient_id DESC LIMIT ? OFFSET ?", args + [per_page, (page - 1) * per_page])
    pages = max((total + per_page - 1) // per_page, 1)
    return render_template("patients.html", rows=rows, q=q, page=page, pages=pages,
                           total=total, per_page=per_page)


@app.route("/patients/new", methods=["GET", "POST"])
@roles_required(ADMIN, DOCTOR)
def patient_new():
    form, errors = {}, {}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in (
            "first_name", "last_name", "date_of_birth", "sex", "phone", "email", "address",
            "matric_staff_id", "patient_type", "blood_group", "allergies", "emergency_contact")}
        for field, label in (("first_name", "First name"), ("last_name", "Last name"),
                             ("date_of_birth", "Date of birth"), ("sex", "Sex"),
                             ("phone", "Phone"), ("address", "Address"),
                             ("matric_staff_id", "Matric number / Staff ID"),
                             ("blood_group", "Blood group"),
                             ("emergency_contact", "Emergency contact")):
            if not form[field]:
                errors[field] = f"{label} is required."
        if form["sex"] and form["sex"] not in ("Male", "Female"):
            errors["sex"] = "Choose Male or Female."
        if form["patient_type"] not in ("Student", "Staff"):
            errors["patient_type"] = "Choose Student or Staff."
        if form["blood_group"] and form["blood_group"] not in BLOOD_GROUPS:
            errors["blood_group"] = "Choose a valid blood group."
        phone = normalize_phone(form["phone"])
        if form["phone"] and not phone:
            errors["phone"] = "Enter a valid Nigerian number, e.g. 0803 214 5670 or +234 803 214 5670."
        emergency = normalize_phone(form["emergency_contact"])
        if form["emergency_contact"] and not emergency:
            errors["emergency_contact"] = "Enter a valid Nigerian number."
        if form["date_of_birth"]:
            try:
                dob = date.fromisoformat(form["date_of_birth"])
                if dob > date.today():
                    errors["date_of_birth"] = "Date of birth cannot be in the future."
            except ValueError:
                errors["date_of_birth"] = "Enter a valid date."
        if form["email"] and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", form["email"]):
            errors["email"] = "Enter a valid email address."
        if not errors:
            existing = query("SELECT patient_id, patient_number FROM patients WHERE matric_staff_id=? "
                             "OR (lower(first_name)=lower(?) AND lower(last_name)=lower(?) AND date_of_birth=?)",
                             (form["matric_staff_id"], form["first_name"], form["last_name"],
                              form["date_of_birth"]), one=True)
            if existing:
                flash(f"This patient is already registered as {existing['patient_number']}. "
                      "Duplicate registration was prevented.", "warning")
                return redirect(url_for("patient_detail", pid=existing["patient_id"]))
            db = get_db()
            cur = db.execute(
                "INSERT INTO patients(matric_staff_id, patient_type, first_name, last_name, date_of_birth, "
                "sex, phone, email, address, blood_group, allergies, emergency_contact, registered_by, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (form["matric_staff_id"], form["patient_type"], form["first_name"].title(),
                 form["last_name"].title(), form["date_of_birth"], form["sex"], phone,
                 form["email"] or None, form["address"], form["blood_group"],
                 form["allergies"] or "None", emergency, g.user["user_id"], now()))
            pid = cur.lastrowid
            number = f"P-{10000 + pid}"
            db.execute("UPDATE patients SET patient_number=? WHERE patient_id=?", (number, pid))
            db.commit()
            log_action("Registered patient", f"{number} registered", patient_id=pid)
            flash(f"Patient registered successfully. Patient number: {number}.", "success")
            return redirect(url_for("patient_detail", pid=pid))
    return render_template("patient_form.html", form=form, errors=errors, blood_groups=BLOOD_GROUPS)


@app.route("/patients/<int:pid>")
@login_required
def patient_detail(pid):
    patient = query("SELECT * FROM patients WHERE patient_id=?", (pid,), one=True)
    if patient is None:
        abort(404)
    log_action("Viewed patient record", patient["patient_number"], patient_id=pid)
    clinical = g.user["role_name"] in (ADMIN, DOCTOR)
    consultations, prescriptions = [], []
    if clinical:
        consultations = query(
            "SELECT c.*, u.full_name AS doctor_name, "
            "(SELECT group_concat(diagnosis_text, '; ') FROM diagnoses d WHERE d.consultation_id=c.consultation_id) AS diagnosis "
            "FROM consultations c JOIN users u ON u.user_id=c.doctor_id WHERE c.patient_id=? "
            "ORDER BY c.consultation_date DESC", (pid,))
        prescriptions = query(
            "SELECT pr.*, c.consultation_date FROM prescriptions pr JOIN consultations c "
            "ON c.consultation_id=pr.consultation_id WHERE c.patient_id=? ORDER BY pr.prescription_id DESC", (pid,))
    labs = query(
        "SELECT lr.*, u.full_name AS requested_name, res.result_text, res.remarks, res.result_date "
        "FROM laboratory_requests lr JOIN users u ON u.user_id=lr.requested_by "
        "LEFT JOIN laboratory_results res ON res.request_id=lr.request_id "
        "WHERE lr.patient_id=? ORDER BY lr.request_id DESC", (pid,))
    appts = query(
        "SELECT a.*, u.full_name AS doctor_name FROM appointments a JOIN users u ON u.user_id=a.doctor_id "
        "WHERE a.patient_id=? AND a.status='Scheduled' AND a.appointment_date >= ? "
        "ORDER BY a.appointment_date, a.appointment_time", (pid, today()))
    return render_template("patient_detail.html", p=patient, consultations=consultations,
                           prescriptions=prescriptions, labs=labs, appts=appts, clinical=clinical)


# --------------------------------------------------------------------------
# Consultation, diagnosis, prescriptions and lab requests
# --------------------------------------------------------------------------
@app.route("/patients/<int:pid>/consult", methods=["GET", "POST"])
@roles_required(DOCTOR)
def consult(pid):
    patient = query("SELECT * FROM patients WHERE patient_id=?", (pid,), one=True)
    if patient is None:
        abort(404)
    appts = query("SELECT * FROM appointments WHERE patient_id=? AND doctor_id=? AND status='Scheduled' "
                  "ORDER BY appointment_date", (pid, g.user["user_id"]))
    form, errors = {}, {}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in (
            "chief_complaint", "symptoms", "blood_pressure", "temperature", "weight",
            "diagnosis", "notes", "appointment_id", "other_test")}
        if not form["chief_complaint"]:
            errors["chief_complaint"] = "Chief complaint is required."
        if not form["diagnosis"]:
            errors["diagnosis"] = "Diagnosis is required."
        if form["blood_pressure"] and not re.match(r"^\d{2,3}/\d{2,3}$", form["blood_pressure"]):
            errors["blood_pressure"] = "Use the format 120/80."
        for key, label in (("temperature", "Temperature"), ("weight", "Weight")):
            if form[key]:
                try:
                    float(form[key])
                except ValueError:
                    errors[key] = f"{label} must be a number."
        drugs = request.form.getlist("drug_name")
        doses = request.form.getlist("dosage")
        freqs = request.form.getlist("frequency")
        durations = request.form.getlist("duration")
        instrs = request.form.getlist("instructions")
        meds = []
        for i, drug in enumerate(drugs):
            drug = drug.strip()
            if not drug:
                continue
            dose = doses[i].strip() if i < len(doses) else ""
            dur = durations[i].strip() if i < len(durations) else ""
            if not dose or not dur:
                errors["medication"] = "Each medication needs a dosage and a duration."
            meds.append((drug, dose, freqs[i].strip() if i < len(freqs) else "", dur,
                         instrs[i].strip() if i < len(instrs) else ""))
        tests = [t for t in request.form.getlist("tests") if t in COMMON_TESTS]
        if form["other_test"]:
            tests.append(form["other_test"][:80])
        appointment_id = None
        if form["appointment_id"]:
            appt = query("SELECT * FROM appointments WHERE appointment_id=? AND patient_id=? AND doctor_id=? "
                         "AND status='Scheduled'", (form["appointment_id"], pid, g.user["user_id"]), one=True)
            if appt:
                appointment_id = appt["appointment_id"]
        if not errors:
            db = get_db()
            cur = db.execute(
                "INSERT INTO consultations(patient_id, doctor_id, appointment_id, consultation_date, chief_complaint, "
                "symptoms, blood_pressure, temperature, weight, notes) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (pid, g.user["user_id"], appointment_id, now(), form["chief_complaint"], form["symptoms"],
                 form["blood_pressure"], form["temperature"], form["weight"], form["notes"]))
            cid = cur.lastrowid
            db.execute("INSERT INTO diagnoses(consultation_id, diagnosis_text) VALUES (?,?)", (cid, form["diagnosis"]))
            for drug, dose, freq, dur, instr in meds:
                db.execute("INSERT INTO prescriptions(consultation_id, drug_name, dosage, frequency, duration, "
                           "instructions, created_at) VALUES (?,?,?,?,?,?,?)", (cid, drug, dose, freq, dur, instr, now()))
            for test in tests:
                db.execute("INSERT INTO laboratory_requests(patient_id, consultation_id, test_name, requested_by, "
                           "request_date) VALUES (?,?,?,?,?)", (pid, cid, test, g.user["user_id"], now()))
            if appointment_id:
                db.execute("UPDATE appointments SET status='Completed' WHERE appointment_id=?", (appointment_id,))
            db.commit()
            log_action("Recorded consultation", f"Diagnosis: {form['diagnosis'][:60]}", patient_id=pid)
            if meds:
                log_action("Prescription issued", ", ".join(m[0] for m in meds)[:80], patient_id=pid)
            if tests:
                log_action("Lab test requested", ", ".join(tests)[:80], patient_id=pid)
            flash("Consultation saved to the patient's record.", "success")
            return redirect(url_for("patient_detail", pid=pid))
    return render_template("consult_form.html", p=patient, form=form, errors=errors, appts=appts,
                           tests=COMMON_TESTS, frequencies=FREQUENCIES)


@app.route("/prescriptions")
@roles_required(ADMIN, DOCTOR)
def prescriptions():
    status = request.args.get("status", "")
    q = request.args.get("q", "").strip()
    sql = ("SELECT pr.*, p.patient_id, p.first_name || ' ' || p.last_name AS patient_name, p.patient_number, "
           "u.full_name AS doctor_name FROM prescriptions pr "
           "JOIN consultations c ON c.consultation_id=pr.consultation_id "
           "JOIN patients p ON p.patient_id=c.patient_id JOIN users u ON u.user_id=c.doctor_id WHERE 1=1")
    args = []
    if status in ("Pending", "Dispensed"):
        sql += " AND pr.status=?"
        args.append(status)
    if q:
        sql += " AND (p.first_name || ' ' || p.last_name LIKE ? OR pr.drug_name LIKE ? OR p.patient_number LIKE ?)"
        args += [f"%{q}%"] * 3
    rows = query(sql + " ORDER BY pr.prescription_id DESC LIMIT 100", args)
    return render_template("prescriptions.html", rows=rows, status=status, q=q)


@app.route("/prescriptions/<int:rid>/dispense", methods=["POST"])
@roles_required(ADMIN, DOCTOR)
def dispense(rid):
    row = query("SELECT pr.*, c.patient_id FROM prescriptions pr JOIN consultations c "
                "ON c.consultation_id=pr.consultation_id WHERE pr.prescription_id=?", (rid,), one=True)
    if row is None:
        abort(404)
    execute("UPDATE prescriptions SET status='Dispensed' WHERE prescription_id=?", (rid,))
    log_action("Prescription dispensed", f"RX{100000 + rid} - {row['drug_name']}", patient_id=row["patient_id"])
    flash("Prescription marked as dispensed.", "success")
    return redirect(request.form.get("back") if safe_next(request.form.get("back")) else url_for("prescriptions"))


# --------------------------------------------------------------------------
# Laboratory
# --------------------------------------------------------------------------
@app.route("/lab")
@login_required
def lab():
    status = request.args.get("status", "")
    q = request.args.get("q", "").strip()
    sql = ("SELECT lr.*, p.first_name || ' ' || p.last_name AS patient_name, p.patient_number, "
           "u.full_name AS requested_name, res.result_text FROM laboratory_requests lr "
           "JOIN patients p ON p.patient_id=lr.patient_id JOIN users u ON u.user_id=lr.requested_by "
           "LEFT JOIN laboratory_results res ON res.request_id=lr.request_id WHERE 1=1")
    args = []
    if status in ("Pending", "Completed"):
        sql += " AND lr.status=?"
        args.append(status)
    if q:
        sql += " AND (p.first_name || ' ' || p.last_name LIKE ? OR lr.test_name LIKE ? OR p.patient_number LIKE ?)"
        args += [f"%{q}%"] * 3
    rows = query(sql + " ORDER BY (lr.status='Pending') DESC, lr.request_id DESC LIMIT 100", args)
    return render_template("lab.html", rows=rows, status=status, q=q)


@app.route("/lab/new", methods=["GET", "POST"])
@roles_required(ADMIN, DOCTOR)
def lab_new():
    error = None
    patients_list = query("SELECT patient_id, patient_number, first_name, last_name FROM patients ORDER BY first_name")
    if request.method == "POST":
        pid = request.form.get("patient_id", "")
        test = request.form.get("test_name", "").strip()
        other = request.form.get("other_test", "").strip()
        test = other or test
        patient = query("SELECT * FROM patients WHERE patient_id=?", (pid,), one=True)
        if patient is None or not test:
            error = "Select a patient and a test."
        else:
            execute("INSERT INTO laboratory_requests(patient_id, test_name, requested_by, request_date) "
                    "VALUES (?,?,?,?)", (patient["patient_id"], test[:80], g.user["user_id"], now()))
            log_action("Lab test requested", test[:80], patient_id=patient["patient_id"])
            flash("Laboratory request created.", "success")
            return redirect(url_for("lab"))
    return render_template("lab_new.html", patients=patients_list, tests=COMMON_TESTS, error=error)


@app.route("/lab/<int:rid>", methods=["GET", "POST"])
@login_required
def lab_result(rid):
    req = query("SELECT lr.*, p.first_name || ' ' || p.last_name AS patient_name, p.patient_number, "
                "u.full_name AS requested_name FROM laboratory_requests lr "
                "JOIN patients p ON p.patient_id=lr.patient_id JOIN users u ON u.user_id=lr.requested_by "
                "WHERE lr.request_id=?", (rid,), one=True)
    if req is None:
        abort(404)
    result = query("SELECT res.*, u.full_name AS entered_name FROM laboratory_results res "
                   "JOIN users u ON u.user_id=res.entered_by WHERE res.request_id=?", (rid,), one=True)
    error = None
    if request.method == "POST":
        if g.user["role_name"] != LAB:
            abort(403)
        text = request.form.get("result_text", "").strip()
        remarks = request.form.get("remarks", "").strip()
        if result is not None:
            error = "A result has already been recorded for this request."
        elif not text:
            error = "Enter the test result."
        else:
            db = get_db()
            db.execute("INSERT INTO laboratory_results(request_id, result_text, remarks, entered_by, result_date) "
                       "VALUES (?,?,?,?,?)", (rid, text, remarks, g.user["user_id"], now()))
            db.execute("UPDATE laboratory_requests SET status='Completed' WHERE request_id=?", (rid,))
            db.commit()
            log_action("Lab result entered", f"{req['test_name']} ({rid})", patient_id=req["patient_id"])
            flash("Result saved to the patient's record.", "success")
            return redirect(url_for("lab"))
    return render_template("lab_result.html", r=req, result=result, error=error)


# --------------------------------------------------------------------------
# Appointments
# --------------------------------------------------------------------------
@app.route("/appointments", methods=["GET", "POST"])
@roles_required(ADMIN, DOCTOR)
def appointments():
    doctors = query("SELECT u.user_id, u.full_name FROM users u JOIN roles r ON r.role_id=u.role_id "
                    "WHERE r.role_name=? AND u.status='active' ORDER BY u.full_name", (DOCTOR,))
    patients_list = query("SELECT patient_id, patient_number, first_name, last_name FROM patients ORDER BY first_name")
    form, error = {}, None
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in
                ("patient_id", "doctor_id", "appointment_date", "appointment_time", "reason")}
        patient = query("SELECT * FROM patients WHERE patient_id=?", (form["patient_id"],), one=True)
        doctor = query("SELECT u.* FROM users u JOIN roles r ON r.role_id=u.role_id WHERE u.user_id=? "
                       "AND r.role_name=?", (form["doctor_id"], DOCTOR), one=True)
        try:
            day = date.fromisoformat(form["appointment_date"])
        except ValueError:
            day = None
        if not patient or not doctor:
            error = "Select a patient and a doctor."
        elif day is None or day < date.today():
            error = "Choose today or a future date."
        elif form["appointment_time"] not in APPOINTMENT_SLOTS:
            error = "Choose a valid time slot (08:00 - 16:00)."
        else:
            clash = query("SELECT 1 FROM appointments WHERE doctor_id=? AND appointment_date=? AND "
                          "appointment_time=? AND status != 'Cancelled'",
                          (doctor["user_id"], form["appointment_date"], form["appointment_time"]), one=True)
            if clash:
                alt = next_free_slot(doctor["user_id"], form["appointment_date"], form["appointment_time"])
                error = (f"{doctor['full_name']} is not available at {form['appointment_time']}. "
                         + (f"Next available slot that day: {alt}." if alt else "No more slots that day."))
                if alt:
                    form["appointment_time"] = alt
            else:
                # cancelled rows would violate the UNIQUE constraint, so reuse them
                execute("DELETE FROM appointments WHERE doctor_id=? AND appointment_date=? AND "
                        "appointment_time=? AND status='Cancelled'",
                        (doctor["user_id"], form["appointment_date"], form["appointment_time"]))
                execute("INSERT INTO appointments(patient_id, doctor_id, appointment_date, appointment_time, reason, "
                        "created_at) VALUES (?,?,?,?,?,?)", (patient["patient_id"], doctor["user_id"],
                        form["appointment_date"], form["appointment_time"], form["reason"], now()))
                log_action("Appointment booked", f"{form['appointment_date']} {form['appointment_time']} "
                           f"with {doctor['full_name']}", patient_id=patient["patient_id"])
                flash("Appointment booked. Confirmation recorded.", "success")
                return redirect(url_for("appointments"))
    sql = ("SELECT a.*, p.first_name || ' ' || p.last_name AS patient_name, p.patient_number, "
           "u.full_name AS doctor_name FROM appointments a JOIN patients p ON p.patient_id=a.patient_id "
           "JOIN users u ON u.user_id=a.doctor_id WHERE a.status='Scheduled' AND a.appointment_date >= ?")
    args = [today()]
    if g.user["role_name"] == DOCTOR:
        sql += " AND a.doctor_id=?"
        args.append(g.user["user_id"])
    rows = query(sql + " ORDER BY a.appointment_date, a.appointment_time", args)
    return render_template("appointments.html", rows=rows, doctors=doctors, patients=patients_list,
                           slots=APPOINTMENT_SLOTS, form=form, error=error, min_date=today())


@app.route("/appointments/<int:aid>/cancel", methods=["POST"])
@roles_required(ADMIN, DOCTOR)
def appointment_cancel(aid):
    appt = query("SELECT * FROM appointments WHERE appointment_id=?", (aid,), one=True)
    if appt is None:
        abort(404)
    execute("UPDATE appointments SET status='Cancelled' WHERE appointment_id=?", (aid,))
    log_action("Appointment cancelled", f"{appt['appointment_date']} {appt['appointment_time']}",
               patient_id=appt["patient_id"])
    flash("Appointment cancelled.", "info")
    return redirect(url_for("appointments"))


# --------------------------------------------------------------------------
# Reports, user administration, audit log
# --------------------------------------------------------------------------
@app.route("/reports")
@roles_required(ADMIN, DOCTOR)
def reports():
    end = request.args.get("to") or today()
    start = request.args.get("from") or (date.today() - timedelta(days=29)).isoformat()
    try:
        date.fromisoformat(start), date.fromisoformat(end)
    except ValueError:
        start, end = (date.today() - timedelta(days=29)).isoformat(), today()
    r = {
        "patients": query("SELECT COUNT(*) c FROM patients WHERE substr(created_at,1,10) BETWEEN ? AND ?",
                          (start, end), one=True)["c"],
        "consults": query("SELECT COUNT(*) c FROM consultations WHERE substr(consultation_date,1,10) BETWEEN ? AND ?",
                          (start, end), one=True)["c"],
        "rx": query("SELECT COUNT(*) c FROM prescriptions WHERE substr(created_at,1,10) BETWEEN ? AND ?",
                    (start, end), one=True)["c"],
        "labs": query("SELECT COUNT(*) c FROM laboratory_requests WHERE substr(request_date,1,10) BETWEEN ? AND ?",
                      (start, end), one=True)["c"],
    }
    daily = query("SELECT substr(consultation_date,1,10) AS day, COUNT(*) AS n FROM consultations "
                  "WHERE substr(consultation_date,1,10) BETWEEN ? AND ? GROUP BY day ORDER BY day DESC",
                  (start, end))
    diagnoses = query("SELECT d.diagnosis_text AS name, COUNT(*) AS n FROM diagnoses d JOIN consultations c "
                      "ON c.consultation_id=d.consultation_id WHERE substr(c.consultation_date,1,10) BETWEEN ? AND ? "
                      "GROUP BY lower(d.diagnosis_text) ORDER BY n DESC LIMIT 8", (start, end))
    drugs = query("SELECT drug_name AS name, COUNT(*) AS n FROM prescriptions WHERE substr(created_at,1,10) "
                  "BETWEEN ? AND ? GROUP BY lower(drug_name) ORDER BY n DESC LIMIT 8", (start, end))
    tests = query("SELECT test_name AS name, COUNT(*) AS n, SUM(status='Completed') AS done FROM laboratory_requests "
                  "WHERE substr(request_date,1,10) BETWEEN ? AND ? GROUP BY test_name ORDER BY n DESC", (start, end))
    return render_template("reports.html", r=r, daily=daily, diagnoses=diagnoses, drugs=drugs,
                           tests=tests, start=start, end=end)


@app.route("/users", methods=["GET", "POST"])
@roles_required(ADMIN)
def users():
    form, error = {}, None
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in ("full_name", "username", "role")}
        password = request.form.get("password", "")
        if not form["full_name"] or not form["username"] or form["role"] not in ROLES:
            error = "Full name, username and role are required."
        elif not re.match(r"^[a-z0-9._-]{3,30}$", form["username"].lower()):
            error = "Username must be 3-30 letters, numbers, dots, dashes or underscores."
        elif len(password) < 8 or password.isalpha() or password.isdigit():
            error = "Password must be at least 8 characters and mix letters with numbers."
        elif query("SELECT 1 FROM users WHERE lower(username)=?", (form["username"].lower(),), one=True):
            error = "That username is already taken."
        else:
            role = query("SELECT role_id FROM roles WHERE role_name=?", (form["role"],), one=True)
            uid = execute("INSERT INTO users(role_id, full_name, username, password_hash, staff_number, created_at) "
                          "VALUES (?,?,?,?,?,?)", (role["role_id"], form["full_name"], form["username"].lower(),
                          hash_password(password), None, now()))
            execute("UPDATE users SET staff_number=? WHERE user_id=?", (f"STF{1000 + uid}", uid))
            log_action("User created", f"{form['username'].lower()} ({form['role']})")
            flash("User account created.", "success")
            return redirect(url_for("users"))
    rows = query("SELECT u.*, r.role_name FROM users u JOIN roles r ON r.role_id=u.role_id ORDER BY u.user_id")
    return render_template("users.html", rows=rows, form=form, error=error, roles=ROLES)


@app.route("/users/<int:uid>/toggle", methods=["POST"])
@roles_required(ADMIN)
def user_toggle(uid):
    user = query("SELECT * FROM users WHERE user_id=?", (uid,), one=True)
    if user is None:
        abort(404)
    if uid == g.user["user_id"]:
        flash("You cannot deactivate your own account.", "warning")
    else:
        new = "inactive" if user["status"] == "active" else "active"
        execute("UPDATE users SET status=? WHERE user_id=?", (new, uid))
        log_action("User status changed", f"{user['username']} set to {new}")
        flash(f"{user['full_name']} is now {new}.", "info")
    return redirect(url_for("users"))


@app.route("/audit")
@roles_required(ADMIN)
def audit():
    rows = query("SELECT a.*, u.full_name AS staff_name, p.patient_number FROM audit_log a "
                 "LEFT JOIN users u ON u.user_id=a.user_id LEFT JOIN patients p ON p.patient_id=a.patient_id "
                 "ORDER BY a.created_at DESC, a.log_id DESC LIMIT 200")
    return render_template("audit.html", rows=rows)


# --------------------------------------------------------------------------
# Command line helpers:  flask --app app init-db / seed-demo
# --------------------------------------------------------------------------
@app.cli.command("init-db")
def init_db_command():
    """Create a fresh database (erases existing data)."""
    init_db()
    click.echo("Database created.")


@app.cli.command("seed-demo")
def seed_demo_command():
    """Load demonstration users and Nigerian sample patients."""
    from seed_data import seed_demo
    with app.app_context():
        seed_demo()
    click.echo("Demo data loaded. See README.md for the demo logins.")


if __name__ == "__main__":
    app.run(debug=False)
