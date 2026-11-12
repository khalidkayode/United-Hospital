# United Hospital – Electronic Patient Record Management System (EPR)

A web-based Electronic Patient Record system built for the CSC 476 group project
(Group 13, Department of Computer Science, University of Ibadan).
It replaces paper patient files with a secure, role-based, database-driven application.

**Stack:** Python 3 · Flask · SQLite (relational, Third Normal Form) · HTML/CSS/JavaScript · pytest

## Features (mapped to the project modules)

| Module | What it does |
|---|---|
| Authentication | Login with username, password and role; hashed passwords; secure logout; CSRF protection |
| Role-based access | Administrator, Doctor and Laboratory roles see and do different things |
| Patient registration | Validated form (Nigerian phone numbers, DOB), automatic patient number, duplicate prevention |
| Patient records | Search by name, ID, matric/staff ID or phone; full medical history timeline |
| Consultation & diagnosis | Vital signs, complaint, symptoms, diagnosis, doctor's notes |
| Prescriptions | Multiple drugs per consultation; pending/dispensed tracking |
| Laboratory | Requests from consultations; lab staff enter results; results appear on the patient record |
| Appointments | Booking with doctor-availability check and next-free-slot suggestion |
| Reports | Patients, consultations, prescriptions, lab requests, top diagnoses and drugs for any date range |
| User administration | Admin creates users and activates/deactivates accounts |
| Audit log | Every important action (logins, registrations, consultations, access denied…) is recorded |

## Run it on your computer

Requires Python 3.9 or newer.

```bash
# 1. open a terminal in this folder, then create a virtual environment
python -m venv venv

# 2. activate it
#    Windows (Command Prompt):   venv\Scripts\activate
#    Windows (PowerShell):       venv\Scripts\Activate.ps1
#    macOS / Linux:              source venv/bin/activate

# 3. install the requirement
pip install -r requirements.txt

# 4. create the database and load the demo data
flask --app app init-db
flask --app app seed-demo

# 5. start the system
flask --app app run
```

Open **http://127.0.0.1:5000** in your browser.

## Demo logins (change these before any real use)

| Role | Username | Password |
|---|---|---|
| Administrator | `femi.adewale` | `Admin@123` |
| Doctor | `ngozi.eze` | `Doctor@123` |
| Doctor | `tunde.bakare` | `Doctor@456` |
| Laboratory | `chinedu.okafor` | `Lab@12345` |

On the login page choose the matching role from the **Select Role** list.

## Run the automated tests

```bash
pip install pytest
python -m pytest -v
```

The tests TC1–TC7 correspond to the functional test cases in Chapter 4 of the write-up
(login, invalid login, patient registration, patient search, consultation, prescription, laboratory result).
Further tests cover role-based access, CSRF protection, password hashing, duplicate prevention,
input validation, appointment conflicts and audit logging.

## Project structure

```
app.py            Flask application (routes, validation, security, CLI commands)
schema.sql        Database schema (roles, users, patients, appointments, consultations,
                  diagnoses, prescriptions, laboratory_requests, laboratory_results, audit_log)
seed_data.py      Demo users and Nigerian sample patients
templates/        HTML pages (Jinja2)
static/           Stylesheet and logo
tests/            Automated tests (pytest)
requirements.txt  Python dependency (Flask)
```

## Security notes

- Passwords are stored only as salted hashes (never plain text).
- Every form is protected with a CSRF token; sessions use HTTP-only cookies.
- Each page checks the user's role on the server; patients' clinical notes are hidden from laboratory staff.
- All database queries are parameterised (no SQL injection).
- The demo data are fictional. Do **not** store real patient data without institutional approval and
  proper data-protection controls (see Limitations in the write-up).
- To reset the demo data at any time, run the two commands in step 4 again.

## Configuration (optional environment variables)

`SECRET_KEY` (session signing key; auto-generated in `instance/` if not set), `EPR_DATABASE` (database path),
`HOSPITAL_NAME` (name shown in the interface, default "United Hospital").
