-- United Hospital EPR - relational schema (Third Normal Form)
PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS laboratory_results;
DROP TABLE IF EXISTS laboratory_requests;
DROP TABLE IF EXISTS prescriptions;
DROP TABLE IF EXISTS diagnoses;
DROP TABLE IF EXISTS consultations;
DROP TABLE IF EXISTS appointments;
DROP TABLE IF EXISTS patients;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS roles;

CREATE TABLE roles (
    role_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name  TEXT NOT NULL UNIQUE
);

CREATE TABLE users (
    user_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    role_id        INTEGER NOT NULL REFERENCES roles(role_id),
    full_name      TEXT NOT NULL,
    username       TEXT NOT NULL UNIQUE,
    password_hash  TEXT NOT NULL,
    staff_number   TEXT UNIQUE,
    status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
    created_at     TEXT NOT NULL
);

CREATE TABLE patients (
    patient_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_number     TEXT UNIQUE,
    matric_staff_id    TEXT NOT NULL UNIQUE,
    patient_type       TEXT NOT NULL CHECK (patient_type IN ('Student','Staff')),
    first_name         TEXT NOT NULL,
    last_name          TEXT NOT NULL,
    date_of_birth      TEXT NOT NULL,
    sex                TEXT NOT NULL CHECK (sex IN ('Male','Female')),
    phone              TEXT NOT NULL,
    email              TEXT,
    address            TEXT NOT NULL,
    blood_group        TEXT NOT NULL,
    allergies          TEXT NOT NULL DEFAULT 'None',
    emergency_contact  TEXT NOT NULL,
    registered_by      INTEGER REFERENCES users(user_id),
    created_at         TEXT NOT NULL
);

CREATE TABLE appointments (
    appointment_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id        INTEGER NOT NULL REFERENCES patients(patient_id),
    doctor_id         INTEGER NOT NULL REFERENCES users(user_id),
    appointment_date  TEXT NOT NULL,
    appointment_time  TEXT NOT NULL,
    reason            TEXT,
    status            TEXT NOT NULL DEFAULT 'Scheduled' CHECK (status IN ('Scheduled','Completed','Cancelled')),
    created_at        TEXT NOT NULL,
    UNIQUE (doctor_id, appointment_date, appointment_time)
);

CREATE TABLE consultations (
    consultation_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id         INTEGER NOT NULL REFERENCES patients(patient_id),
    doctor_id          INTEGER NOT NULL REFERENCES users(user_id),
    appointment_id     INTEGER UNIQUE REFERENCES appointments(appointment_id),
    consultation_date  TEXT NOT NULL,
    chief_complaint    TEXT NOT NULL,
    symptoms           TEXT,
    blood_pressure     TEXT,
    temperature        TEXT,
    weight             TEXT,
    notes              TEXT
);

CREATE TABLE diagnoses (
    diagnosis_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    consultation_id  INTEGER NOT NULL REFERENCES consultations(consultation_id) ON DELETE CASCADE,
    diagnosis_text   TEXT NOT NULL
);

CREATE TABLE prescriptions (
    prescription_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    consultation_id  INTEGER NOT NULL REFERENCES consultations(consultation_id) ON DELETE CASCADE,
    drug_name        TEXT NOT NULL,
    dosage           TEXT NOT NULL,
    frequency        TEXT,
    duration         TEXT NOT NULL,
    instructions     TEXT,
    status           TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending','Dispensed')),
    created_at       TEXT NOT NULL
);

CREATE TABLE laboratory_requests (
    request_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id       INTEGER NOT NULL REFERENCES patients(patient_id),
    consultation_id  INTEGER REFERENCES consultations(consultation_id) ON DELETE SET NULL,
    test_name        TEXT NOT NULL,
    requested_by     INTEGER NOT NULL REFERENCES users(user_id),
    request_date     TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending','Completed'))
);

CREATE TABLE laboratory_results (
    result_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id   INTEGER NOT NULL UNIQUE REFERENCES laboratory_requests(request_id) ON DELETE CASCADE,
    result_text  TEXT NOT NULL,
    remarks      TEXT,
    entered_by   INTEGER NOT NULL REFERENCES users(user_id),
    result_date  TEXT NOT NULL
);

CREATE TABLE audit_log (
    log_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES users(user_id),
    patient_id  INTEGER REFERENCES patients(patient_id),
    action      TEXT NOT NULL,
    details     TEXT,
    created_at  TEXT NOT NULL
);

CREATE INDEX idx_patients_name ON patients(last_name, first_name);
CREATE INDEX idx_consult_patient ON consultations(patient_id);
CREATE INDEX idx_labreq_patient ON laboratory_requests(patient_id);
CREATE INDEX idx_audit_created ON audit_log(created_at);
