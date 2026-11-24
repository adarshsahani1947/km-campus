import os
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_NAME = os.path.join(BASE_DIR, "database.db")
PLAIN_PW_DB_NAME = os.path.join(BASE_DIR, "plain_password.db")

VALID_PLAIN_ROLES = {"students", "teachers", "admin"}


def get_db_connection(db_path=DB_NAME, timeout=30.0):
    """Returns a SQLite connection with Row factory, busy timeout, and foreign keys enabled."""
    conn = sqlite3.connect(db_path, timeout=timeout)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_plain_pw_db(db_path=PLAIN_PW_DB_NAME):
    """Initializes plain_password.db with separate tables for students, teachers, and admin."""
    conn = get_db_connection(db_path=db_path)
    cur = conn.cursor()
    for table in ("students", "teachers", "admin"):
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {table} (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                plain_password TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
    conn.commit()
    conn.close()


def sync_plain_password(role, user_id, username, plain_password, db_path=PLAIN_PW_DB_NAME):
    """
    Stores/updates plain-text password in plain_password.db under 'students',
    'teachers', or 'admin'. Safe to ignore/delete in production if not needed.
    """
    if role not in VALID_PLAIN_ROLES or not user_id or not plain_password:
        return
    init_plain_pw_db(db_path=db_path)
    conn = get_db_connection(db_path=db_path)
    conn.execute(
        f"""
        INSERT INTO {role} (user_id, username, plain_password, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            username = excluded.username,
            plain_password = excluded.plain_password,
            updated_at = excluded.updated_at
        """,
        (user_id, (username or "").strip(), plain_password, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.commit()
    conn.close()


def _add_missing_columns(cursor, table_name, col_defs):
    cursor.execute(f"PRAGMA table_info({table_name})")
    existing = {r["name"] for r in cursor.fetchall()}
    for col_name, col_type in col_defs.items():
        if col_name not in existing:
            cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}")


def init_db():
    """Initializes all tables in database.db with hashed passwords for student, teacher, and admin."""
    conn = get_db_connection(db_path=DB_NAME)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL DEFAULT 'Administrator',
            email TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            updated_at TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS teachers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            subject TEXT DEFAULT 'General',
            phone TEXT DEFAULT '',
            email TEXT DEFAULT '',
            updated_at TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            father_name TEXT,
            mother_name TEXT,
            dob TEXT,
            gender TEXT,
            phone TEXT,
            aadhaar TEXT,
            batch TEXT DEFAULT 'Morning Batch',
            school_class TEXT,
            country TEXT,
            state TEXT,
            district TEXT,
            subdivision TEXT,
            block TEXT,
            panchayat TEXT,
            village TEXT,
            post TEXT,
            police_station TEXT,
            pincode TEXT,
            photo TEXT,
            aadhaar_doc TEXT,
            status TEXT DEFAULT 'Pending',
            deactivated_at TEXT,
            leaving_reason TEXT,
            approved_by_teacher TEXT,
            approved_by_role TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS fees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            month_year TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT DEFAULT 'Unpaid',
            payment_date TEXT,
            receipt_no TEXT,
            payment_mode TEXT DEFAULT 'Cash',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES students (id) ON DELETE CASCADE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS profile_edit_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            name TEXT,
            father_name TEXT,
            dob TEXT,
            gender TEXT,
            aadhaar TEXT,
            proof_doc TEXT,
            status TEXT DEFAULT 'Pending',
            requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES students (id) ON DELETE CASCADE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            att_date TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Present',
            batch TEXT,
            remark TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(student_id, att_date),
            FOREIGN KEY (student_id) REFERENCES students (id) ON DELETE CASCADE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS teacher_activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER,
            action_type TEXT NOT NULL,
            detail TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    _add_missing_columns(cur, "admin", {
        "full_name": "TEXT NOT NULL DEFAULT 'Administrator'",
        "email": "TEXT DEFAULT ''",
        "phone": "TEXT DEFAULT ''",
        "updated_at": "TEXT",
    })
    _add_missing_columns(cur, "students", {
        "password_hash": "TEXT",
        "mother_name": "TEXT",
        "school_class": "TEXT",
        "country": "TEXT",
        "state": "TEXT",
        "subdivision": "TEXT",
        "block": "TEXT",
        "panchayat": "TEXT",
        "police_station": "TEXT",
        "pincode": "TEXT",
        "aadhaar_doc": "TEXT",
        "deactivated_at": "TEXT",
        "leaving_reason": "TEXT",
        "approved_by_teacher": "TEXT",
        "approved_by_role": "TEXT",
    })
    _add_missing_columns(cur, "fees", {
        "payment_mode": "TEXT DEFAULT 'Cash'",
        "created_at": "TEXT",
    })

    # Seed default admin if none exists
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if not cur.execute("SELECT id FROM admin LIMIT 1").fetchone():
        admin_user = os.environ.get("KM_ADMIN_USER", "Adarsh")
        admin_pw = os.environ.get("KM_ADMIN_PASS", "Adarsh@123")
        cur.execute(
            "INSERT INTO admin (username, password_hash, full_name, email, phone, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (admin_user, generate_password_hash(admin_pw), "Adarsh Sahani", "", "", now_str),
        )
        aid = cur.lastrowid
        conn.commit()
        sync_plain_password("admin", aid, admin_user, admin_pw)

    # Seed default teacher if none exists
    if not cur.execute("SELECT id FROM teachers LIMIT 1").fetchone():
        t_user = "teacher"
        t_pw = "Teacher@123"
        cur.execute(
            "INSERT INTO teachers (username, password_hash, full_name, subject, phone, email, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (t_user, generate_password_hash(t_pw), "KM Campus Faculty", "Science & Maths", "", "", now_str),
        )
        tid = cur.lastrowid
        conn.commit()
        sync_plain_password("teachers", tid, t_user, t_pw)

    conn.commit()
    conn.close()