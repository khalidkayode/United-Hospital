"""Automated tests for the United Hospital EPR.

TC1-TC7 correspond to the functional test cases in Chapter 4 (Table 4.10) of the
project write-up. The remaining tests cover security and validation rules.
Run with:  python -m pytest -v
"""
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as epr  # noqa: E402
from seed_data import seed_demo  # noqa: E402


@pytest.fixture()
def client(tmp_path):
    epr.app.config["DATABASE"] = str(tmp_path / "test.db")
    epr.app.config["TESTING"] = True
    seed_demo()
    with epr.app.test_client() as c:
        yield c


def token(client):
    client.get("/login")
    with client.session_transaction() as s:
        return s["csrf_token"]


def post(client, url, data=None, **kw):
    data = dict(data or {})
    with client.session_transaction() as s:
        s.setdefault("csrf_token", "t0k3n")
        data["csrf_token"] = s["csrf_token"]
    return client.post(url, data=data, follow_redirects=True, **kw)


def login(client, username, password, role):
    token(client)
    return post(client, "/login", {"username": username, "password": password, "role": role})


def as_doctor(client):
    return login(client, "ngozi.eze", "Doctor@123", "Doctor")


def as_admin(client):
    return login(client, "femi.adewale", "Admin@123", "Administrator")


def as_lab(client):
    return login(client, "chinedu.okafor", "Lab@12345", "Laboratory")


def db_one(sql, args=()):
    with epr.app.app_context():
        return epr.query(sql, args, one=True)


NEW_PATIENT = {
    "first_name": "Kunle", "last_name": "Balogun", "date_of_birth": "1995-07-12", "sex": "Male",
    "phone": "+234 803 555 0147", "email": "kunle.balogun@uhs.edu.ng", "address": "8 Challenge, Ibadan, Oyo State",
    "matric_staff_id": "MAT20231001", "patient_type": "Student", "blood_group": "O+",
    "allergies": "None", "emergency_contact": "08012345678",
}


# ---------------- TC1-TC7: functional test cases ----------------
def test_tc1_valid_login_goes_to_dashboard(client):
    r = as_doctor(client)
    assert r.status_code == 200 and b"Dashboard" in r.data and b"Dr. Ngozi Eze" in r.data


def test_tc2_invalid_login_shows_error(client):
    r = login(client, "ngozi.eze", "wrong-password", "Doctor")
    assert b"Invalid username, password or role" in r.data
    assert b"Login to EPR System" in r.data


def test_tc3_patient_registration(client):
    as_admin(client)
    r = post(client, "/patients/new", NEW_PATIENT)
    assert b"Patient registered successfully" in r.data
    row = db_one("SELECT * FROM patients WHERE matric_staff_id='MAT20231001'")
    assert row["patient_number"].startswith("P-1") and row["phone"] == "08035550147"


def test_tc4_patient_search(client):
    as_doctor(client)
    r = client.get("/patients?q=Makinde")
    assert b"Seyi Makinde" in r.data
    r = client.get("/patients?q=0803 214")
    assert b"Seyi Makinde" in r.data
    r = client.get("/patients?q=Nobody")
    assert b"No matching patient record found" in r.data


def test_tc5_consultation_stored_under_record(client):
    as_doctor(client)
    pid = db_one("SELECT patient_id FROM patients WHERE first_name='Bola'")["patient_id"]
    r = post(client, f"/patients/{pid}/consult", {
        "chief_complaint": "Headache for two days", "symptoms": "Headache, dizziness", "blood_pressure": "130/85",
        "temperature": "36.8", "weight": "81", "diagnosis": "Tension headache", "notes": "Rest and fluids"})
    assert b"Consultation saved" in r.data and b"Tension headache" in r.data
    assert db_one("SELECT COUNT(*) c FROM diagnoses WHERE diagnosis_text='Tension headache'")["c"] == 1


def test_tc6_prescription_saved_and_dispensed(client):
    as_doctor(client)
    pid = db_one("SELECT patient_id FROM patients WHERE first_name='Ebele'")["patient_id"]
    post(client, f"/patients/{pid}/consult", {
        "chief_complaint": "Cough", "diagnosis": "Upper respiratory tract infection",
        "drug_name": ["Amoxicillin 500mg"], "dosage": ["1 capsule"], "frequency": ["Three times daily (TDS)"],
        "duration": ["5 days"], "instructions": ["Take after meals"]})
    rx = db_one("SELECT * FROM prescriptions WHERE drug_name='Amoxicillin 500mg' ORDER BY prescription_id DESC")
    assert rx is not None and rx["status"] == "Pending"
    r = post(client, f"/prescriptions/{rx['prescription_id']}/dispense")
    assert b"marked as dispensed" in r.data
    assert db_one("SELECT status FROM prescriptions WHERE prescription_id=?", (rx["prescription_id"],))["status"] == "Dispensed"


def test_tc7_lab_result_stored_under_record(client):
    as_lab(client)
    req = db_one("SELECT * FROM laboratory_requests WHERE status='Pending' ORDER BY request_id LIMIT 1")
    r = post(client, f"/lab/{req['request_id']}", {"result_text": "Within normal range", "remarks": "No abnormality"})
    assert b"Result saved" in r.data
    res = db_one("SELECT * FROM laboratory_results WHERE request_id=?", (req["request_id"],))
    assert res["result_text"] == "Within normal range"
    assert db_one("SELECT status FROM laboratory_requests WHERE request_id=?", (req["request_id"],))["status"] == "Completed"


# ---------------- security and validation ----------------
def test_passwords_are_hashed(client):
    with epr.app.app_context():
        for u in epr.query("SELECT password_hash FROM users"):
            assert u["password_hash"] not in ("Admin@123", "Doctor@123", "Lab@12345")
            assert u["password_hash"].startswith(("scrypt:", "pbkdf2:"))


def test_login_required_redirects(client):
    r = client.get("/patients")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_role_based_access(client):
    as_lab(client)
    assert client.get("/patients/new").status_code == 403
    assert client.get("/users").status_code == 403
    assert client.get("/reports").status_code == 403
    pid = db_one("SELECT patient_id FROM patients LIMIT 1")["patient_id"]
    assert client.get(f"/patients/{pid}/consult").status_code == 403
    page = client.get(f"/patients/{pid}")
    assert page.status_code == 200 and b"Medical History Timeline" not in page.data  # lab cannot see clinical notes


def test_doctor_cannot_manage_users_but_admin_can(client):
    as_doctor(client)
    assert client.get("/users").status_code == 403
    client.post("/logout", data={"csrf_token": token(client)})
    as_admin(client)
    assert client.get("/users").status_code == 200 and client.get("/audit").status_code == 200


def test_csrf_protection_blocks_forged_post(client):
    r = client.post("/login", data={"username": "ngozi.eze", "password": "Doctor@123", "role": "Doctor"})
    assert r.status_code == 400


def test_role_mismatch_rejected(client):
    r = login(client, "ngozi.eze", "Doctor@123", "Administrator")
    assert b"Invalid username, password or role" in r.data


def test_duplicate_registration_prevented(client):
    as_admin(client)
    before = db_one("SELECT COUNT(*) c FROM patients")["c"]
    dup = dict(NEW_PATIENT, first_name="Seyi", last_name="Makinde", matric_staff_id="STAFF2041")
    r = post(client, "/patients/new", dup)
    assert b"Duplicate registration was prevented" in r.data
    assert db_one("SELECT COUNT(*) c FROM patients")["c"] == before


def test_invalid_phone_and_dob_rejected(client):
    as_admin(client)
    bad = dict(NEW_PATIENT, phone="12345", date_of_birth="2999-01-01")
    r = post(client, "/patients/new", bad)
    assert b"valid Nigerian number" in r.data and b"cannot be in the future" in r.data
    assert db_one("SELECT 1 FROM patients WHERE matric_staff_id='MAT20231001'") is None


def test_appointment_conflict_suggests_next_slot(client):
    as_doctor(client)
    pid = db_one("SELECT patient_id FROM patients WHERE first_name='Sarafadeen'")["patient_id"]
    did = db_one("SELECT user_id FROM users WHERE username='ngozi.eze'")["user_id"]
    day = re.search(r"\d{4}-\d{2}-\d{2}", db_one("SELECT appointment_date d FROM appointments LIMIT 1")["d"]).group(0)
    # Dr Eze already has 11:30 booked that day (seed data)
    r = post(client, "/appointments", {"patient_id": pid, "doctor_id": did, "appointment_date": day,
                                       "appointment_time": "11:30", "reason": "Review"})
    assert b"not available at 11:30" in r.data and b"Next available slot that day: 12:00" in r.data
    r = post(client, "/appointments", {"patient_id": pid, "doctor_id": did, "appointment_date": day,
                                       "appointment_time": "12:00", "reason": "Review"})
    assert b"Appointment booked" in r.data


def test_audit_log_records_actions(client):
    as_admin(client)
    post(client, "/patients/new", NEW_PATIENT)
    with epr.app.app_context():
        actions = [r["action"] for r in epr.query("SELECT action FROM audit_log")]
    assert "Login" in actions and "Registered patient" in actions


def test_failed_login_is_logged(client):
    login(client, "ngozi.eze", "nope", "Doctor")
    with epr.app.app_context():
        assert epr.query("SELECT 1 FROM audit_log WHERE action='Failed login'", one=True) is not None


def test_dashboard_and_reports_render(client):
    as_admin(client)
    r = client.get("/")
    assert b"Total Patients" in r.data and b"Recent Activities" in r.data
    assert client.get("/reports").status_code == 200
    assert client.get("/prescriptions").status_code == 200
    assert client.get("/lab").status_code == 200


def test_logout_ends_session(client):
    as_doctor(client)
    r = post(client, "/logout")
    assert b"signed out" in r.data
    assert client.get("/patients").status_code == 302


def test_admin_creates_and_deactivates_user(client):
    as_admin(client)
    r = post(client, "/users", {"full_name": "Ife Oladipo", "username": "ife.oladipo", "role": "Laboratory",
                                "password": "Strong#123"})
    assert b"User account created" in r.data
    uid = db_one("SELECT user_id FROM users WHERE username='ife.oladipo'")["user_id"]
    post(client, f"/users/{uid}/toggle")
    assert db_one("SELECT status FROM users WHERE user_id=?", (uid,))["status"] == "inactive"
    weak = post(client, "/users", {"full_name": "X Y", "username": "x.y", "role": "Doctor", "password": "short"})
    assert b"at least 8 characters" in weak.data
