"""Demonstration data for United Hospital EPR (Nigerian names, numbers and places)."""
from datetime import datetime, timedelta

import app as epr

DEMO_USERS = [
    # full name, username, password, role, staff number
    ("Dr. Femi Adewale", "femi.adewale", "Admin@123", epr.ADMIN, "STF1001"),
    ("Dr. Ngozi Eze", "ngozi.eze", "Doctor@123", epr.DOCTOR, "DOC0045"),
    ("Dr. Tunde Bakare", "tunde.bakare", "Doctor@456", epr.DOCTOR, "DOC0046"),
    ("Chinedu Okafor", "chinedu.okafor", "Lab@12345", epr.LAB, "LAB0012"),
]

# first, last, dob, phone, email, address, blood, allergies, emergency, matric/staff id, type
DEMO_PATIENTS = [
    ("Seyi", "Makinde", "1992-05-14", "08032145670", "seyi.makinde@uhs.edu.ng",
     "12 Bodija Estate, Ibadan, Oyo State", "O+", "Penicillin", "08123456789", "STAFF2041", "Staff"),
    ("Bola", "Ahmed", "1984-11-02", "08056123904", "bola.ahmed@uhs.edu.ng",
     "5 Akobo Road, Ibadan, Oyo State", "B+", "None", "08034561209", "STAFF1187", "Staff"),
    ("Ebele", "Jonathan", "1999-03-21", "08027892241", "ebele.jonathan@uhs.edu.ng",
     "Block C, Abadina Hostel, University of Ibadan", "A+", "None", "07031122334", "MAT20211873", "Student"),
    ("Oriyomi", "Hamzat", "1970-08-30", "08073019945", "oriyomi.hamzat@uhs.edu.ng",
     "27 Ring Road, Ibadan, Oyo State", "O-", "Sulphonamides", "08098761234", "STAFF0512", "Staff"),
    ("Sarafadeen", "Alli", "1987-01-09", "08094457789", "sarafadeen.alli@uhs.edu.ng",
     "3 Agodi GRA, Ibadan, Oyo State", "AB+", "None", "08055667788", "STAFF1340", "Staff"),
    ("Abimbola", "Adekambi", "2003-12-17", "09012334455", "abimbola.adekambi@uhs.edu.ng",
     "Room 214, Tedder Hall, University of Ibadan", "A-", "Aspirin", "08167890123", "MAT20221147", "Student"),
]


def seed_demo():
    """Reset the database and load demo users, patients and clinical history."""
    epr.init_db()
    with epr.app.app_context():
        _load(epr.get_db())


def _load(db):
    stamp = lambda dt: dt.strftime("%Y-%m-%d %H:%M:%S")
    today = datetime.now().replace(microsecond=0)

    role_ids = {r["role_name"]: r["role_id"] for r in db.execute("SELECT * FROM roles")}
    uid = {}
    for full, username, pwd, role, staff in DEMO_USERS:
        cur = db.execute(
            "INSERT INTO users(role_id, full_name, username, password_hash, staff_number, created_at) "
            "VALUES (?,?,?,?,?,?)", (role_ids[role], full, username, epr.hash_password(pwd), staff,
                                     stamp(today - timedelta(days=90))))
        uid[username] = cur.lastrowid
    admin, eze, bakare, lab = uid["femi.adewale"], uid["ngozi.eze"], uid["tunde.bakare"], uid["chinedu.okafor"]

    pid = {}
    for i, p in enumerate(DEMO_PATIENTS):
        first, last, dob, phone, email, addr, blood, allergy, emerg, matric, ptype = p
        created = today - timedelta(days=80 - i * 9)
        cur = db.execute(
            "INSERT INTO patients(matric_staff_id, patient_type, first_name, last_name, date_of_birth, sex, phone, "
            "email, address, blood_group, allergies, emergency_contact, registered_by, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (matric, ptype, first, last, dob, "Male", phone, email, addr, blood, allergy, emerg, admin, stamp(created)))
        pid[first] = cur.lastrowid
        db.execute("UPDATE patients SET patient_number=? WHERE patient_id=?", (f"P-{10000 + cur.lastrowid}", cur.lastrowid))
        db.execute("INSERT INTO audit_log(user_id, patient_id, action, details, created_at) VALUES (?,?,?,?,?)",
                   (admin, cur.lastrowid, "Registered patient", f"P-{10000 + cur.lastrowid} registered", stamp(created)))

    def consult(first, doctor, days_ago, hours_ago, complaint, symptoms, bp, temp, wt, diagnosis, notes,
                meds=(), tests=()):
        when = today - timedelta(days=days_ago, hours=hours_ago)
        cur = db.execute(
            "INSERT INTO consultations(patient_id, doctor_id, consultation_date, chief_complaint, symptoms, "
            "blood_pressure, temperature, weight, notes) VALUES (?,?,?,?,?,?,?,?,?)",
            (pid[first], doctor, stamp(when), complaint, symptoms, bp, temp, wt, notes))
        cid = cur.lastrowid
        db.execute("INSERT INTO diagnoses(consultation_id, diagnosis_text) VALUES (?,?)", (cid, diagnosis))
        db.execute("INSERT INTO audit_log(user_id, patient_id, action, details, created_at) VALUES (?,?,?,?,?)",
                   (doctor, pid[first], "Recorded consultation", f"Diagnosis: {diagnosis}", stamp(when)))
        for drug, dose, freq, dur, instr, status in meds:
            db.execute("INSERT INTO prescriptions(consultation_id, drug_name, dosage, frequency, duration, "
                       "instructions, status, created_at) VALUES (?,?,?,?,?,?,?,?)",
                       (cid, drug, dose, freq, dur, instr, status, stamp(when)))
            db.execute("INSERT INTO audit_log(user_id, patient_id, action, details, created_at) VALUES (?,?,?,?,?)",
                       (doctor, pid[first], "Prescription issued", drug, stamp(when + timedelta(minutes=5))))
        for test, result, remarks in tests:
            status = "Completed" if result else "Pending"
            c2 = db.execute("INSERT INTO laboratory_requests(patient_id, consultation_id, test_name, requested_by, "
                            "request_date, status) VALUES (?,?,?,?,?,?)",
                            (pid[first], cid, test, doctor, stamp(when + timedelta(minutes=8)), status))
            db.execute("INSERT INTO audit_log(user_id, patient_id, action, details, created_at) VALUES (?,?,?,?,?)",
                       (doctor, pid[first], "Lab test requested", test, stamp(when + timedelta(minutes=8))))
            if result:
                db.execute("INSERT INTO laboratory_results(request_id, result_text, remarks, entered_by, result_date) "
                           "VALUES (?,?,?,?,?)", (c2.lastrowid, result, remarks, lab, stamp(min(when + timedelta(hours=3), today))))
                db.execute("INSERT INTO audit_log(user_id, patient_id, action, details, created_at) VALUES (?,?,?,?,?)",
                           (lab, pid[first], "Lab result entered", test, stamp(min(when + timedelta(hours=3), today))))

    consult("Seyi", eze, 62, 0, "Fever and body pains for 2 days", "Fever, chills, headache, joint pain",
            "118/76", "38.6", "69", "Uncomplicated malaria",
            "Rest, oral fluids. Return if fever persists beyond 3 days.",
            meds=[("Artemether-Lumefantrine 80/480mg", "4 tablets", "Twice daily (BD)", "3 days",
                   "Take with food", "Dispensed")],
            tests=[("Malaria Parasite (MP)", "Malaria parasite seen (++)", "Treat as per plan")])
    consult("Seyi", eze, 3, 2, "Sore throat and fever for 3 days", "Sore throat, fever (37.2 C), headache, fatigue",
            "120/80", "37.2", "68", "Acute pharyngitis (J02.9) - likely viral infection",
            "Advised rest, increased fluid intake and monitor temperature. Return if symptoms persist beyond 5 days.",
            meds=[("Amoxicillin 500mg", "1 capsule", "Three times daily (TDS)", "5 days",
                   "Take after meals. Complete the full course.", "Dispensed")],
            tests=[("Full Blood Count (CBC)", "WBC 6.8 x10^9/L; RBC 4.9 x10^12/L; Hb 135 g/L", "Within normal range")])
    consult("Bola", eze, 10, 1, "Routine hypertension review", "Occasional headache",
            "148/94", "36.7", "82", "Essential hypertension - follow-up",
            "Blood pressure above target. Dose adjusted. Advised low-salt diet and daily walks.",
            meds=[("Amlodipine 10mg", "1 tablet", "Once daily", "30 days", "Take in the morning", "Pending")],
            tests=[("Lipid Panel", None, None)])
    consult("Ebele", bakare, 1, 3, "Abdominal discomfort and fever", "Abdominal pain, fever, loss of appetite",
            "112/70", "38.1", "64", "Suspected typhoid fever",
            "Widal test requested. Start empirical treatment pending result.",
            meds=[("Ciprofloxacin 500mg", "1 tablet", "Twice daily (BD)", "7 days", "Take after meals", "Pending")],
            tests=[("Widal Test", None, None)])
    consult("Oriyomi", eze, 0, 0.5, "Diabetes review", "Increased thirst, frequent urination",
            "136/86", "36.6", "88", "Type 2 diabetes mellitus - review",
            "Continue current regimen. HbA1c requested to assess long-term control.",
            meds=[("Metformin 500mg", "1 tablet", "Twice daily (BD)", "30 days", "Take with meals", "Pending")],
            tests=[("HbA1c", None, None), ("Fasting Blood Sugar", "7.9 mmol/L", "Slightly elevated")])
    consult("Sarafadeen", bakare, 5, 2, "Epigastric pain after meals", "Heartburn, bloating",
            "122/78", "36.8", "75", "Gastritis",
            "Avoid spicy foods and late meals. Review in two weeks if no improvement.",
            meds=[("Omeprazole 20mg", "1 capsule", "Once daily", "14 days", "Take 30 minutes before breakfast",
                   "Dispensed")])
    consult("Abimbola", bakare, 2, 4, "Fever, chills and headache", "Fever, chills, headache, weakness",
            "110/70", "38.9", "61", "Uncomplicated malaria",
            "Hydrate well. Review if no improvement in 48 hours.",
            meds=[("Artemether-Lumefantrine 80/480mg", "4 tablets", "Twice daily (BD)", "3 days",
                   "Take with food", "Dispensed")],
            tests=[("Malaria Parasite (MP)", "Malaria parasite seen (+++)", "Treatment started")])

    tomorrow = (today + timedelta(days=1)).strftime("%Y-%m-%d")
    for first, doctor, time_, reason in (("Abimbola", bakare, "10:00", "Follow-up after malaria treatment"),
                                         ("Bola", eze, "11:30", "Blood pressure re-check")):
        db.execute("INSERT INTO appointments(patient_id, doctor_id, appointment_date, appointment_time, reason, "
                   "created_at) VALUES (?,?,?,?,?,?)", (pid[first], doctor, tomorrow, time_, reason, stamp(today)))
    db.commit()
