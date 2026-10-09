CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_name TEXT NOT NULL,
    doctor_name TEXT NOT NULL,
    appointment_date TEXT NOT NULL,
    status TEXT NOT NULL,
    notes TEXT
);
