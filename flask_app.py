"""
================================================================================
KM CAMPUS MANAGEMENT SYSTEM — MAIN FLASK APPLICATION (flask_app.py)
================================================================================
Architecture Map (Sections -> Subsections -> Parts):
  SECTION 1  : Imports, App Configuration & File Upload Constants
                 1.1.1 Filesystem & Storage Paths
                 1.2.1 Production Toggle, Upload Limits & Domain Constants
  SECTION 2  : Database Connections, Secret-Key Hashing & Schema Migrations
                 2.1.1 Primary SQLite Connection Helper
                 2.2.1 Secret-Key Password Hashing & Verification
                 2.2.2 Optional Plain-Text Password Mirror (plain_password.db)
                 2.3.1 Individual Table & Column Ensurers
                 2.3.2 Startup Database Bootstrapper
  SECTION 3  : Privacy Masking & Frontend Sanitization Layer
                 3.1.1 Field-Level Masking Rules (Phone, Email, ID Number)
                 3.2.1 Row Sanitizers (Student, Teacher, Edit Request & Fee Views)
  SECTION 4  : Authentication Decorators, Typo Search & Shared Helpers
                 4.1.1 Multi-Role Session Guards (Student, Teacher, Admin)
                 4.2.1 Text, Batch & Request Helpers
                 4.2.2 Upload Validation & Ranked Typo-Tolerant Search Engine
                 4.2.3 Audit Logging, Allowed Fee Window & PDF 1.4 Generator
                 4.2.4 Fee Period, Payment Mode & Session Actor Helpers
                 4.3.1 Shared Student Create & Direct Update Operations
                 4.3.2 Shared Fee Ledger & Suggestion Query Helpers
  SECTION 5  : Public Portal, OTP Verification & Student Registration Routes
                 5.1.1 Portal Home & Registration OTP Endpoints
                 5.2.1 Two-Step Student Self-Registration Flow
  SECTION 6  : Student Portal Routes (Auth, Dashboard & Fee Ledger)
                 6.1.1 Student Authentication & Session Cleanup
                 6.2.1 Student Dashboard & Fee Ledger Views
  SECTION 7  : Admin Core Routes (Auth, Profile, Dashboard, Search & Dossier)
                 7.1.1 Admin Authentication & Profile Management
                 7.2.1 Admin Dashboard, Ranked Typo Search & Student Dossier
  SECTION 8  : Admin Student Lifecycle Routes (Approvals, Edits & Add/Edit)
                 8.1.1 Pending Registration Approval Queue
                 8.2.1 Profile Edit Requests Queue & Inline Updates
                 8.3.1 Direct Register New / Edit Existing Student
  SECTION 9  : Admin Attendance, Roster & Fee Ledger Routes
                 9.1.1 Active/Inactive Status & Daily Attendance Marking
                 9.2.1 Roster Cards & Daily/Monthly Attendance Lookup
                 9.3.1 Fee Collection, Deposit Recording & Printable Ledger
                 9.4.1 Admin Instant Fee Student Suggestions JSON Endpoint
  SECTION 10 : Teacher Portal Routes (Auth, Dashboard, Approvals, Fees & Exports)
                 10.1.1 Teacher Authentication & Session Cleanup
                 10.2.1 Teacher Control Center Dashboard & Ranked Typo Search
                 10.3.1 Pending Admissions & Edit Approvals Queue
                 10.4.1 Teacher Register New / Edit Existing Student
                 10.5.1 Teacher Single-Day Attendance & Class/Monthly Reports
                 10.6.1 Teacher Fee Status, Deposit Updates, Ledgers & Suggestions
                 10.7.1 Teacher Profile & Activity Log
                 10.7.2 Teacher Student Workspace Detail Page
                 10.7.3 Teacher Attendance & Student Profile PDF Exports
  SECTION 11 : Error Handling & Application Entry Point
                 11.1.1 Global 500 Error Handler & WSGI/CLI Entry Point
================================================================================
"""

# ==============================================================================
# SECTION 1: IMPORTS, APP CONFIGURATION & FILE UPLOAD CONSTANTS
# ==============================================================================

# --- 1.1.1 Filesystem & Storage Paths ---
import difflib
import hashlib
import hmac
import os
import random
import re
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "km_campus_s_key")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
# Separate plain-text password store with tables: students, teachers, admin
PLAIN_PASS_DB_PATH = os.path.join(BASE_DIR, "plain_password.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
PHOTOS_FOLDER = os.path.join(UPLOAD_FOLDER, "photos")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PHOTOS_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# --- 1.2.1 Production Toggle, Upload Limits & Domain Constants ---
# Admin credentials live in database.db (`admin` table), never hardcoded here.
# Set ENABLE_PLAIN_PASS_SYNC = False in production if plain-text sync is unwanted.
ENABLE_PLAIN_PASS_SYNC = os.environ.get("ENABLE_PLAIN_PASS_SYNC", "1") == "1"

PHOTO_DISPLAY_MAX_KB = 512
PHOTO_ACTUAL_MAX_BYTES = 600 * 1024
AADHAAR_MAX_BYTES = 700 * 1024
ALLOWED_PHOTO_EXTS = {".jpg", ".jpeg", ".png", ".webp"}
ALLOWED_AADHAAR_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".pdf"}

# Mobile numbers are disclosed unmasked on standard views ONLY for Male candidates
AUTHORISED_PHONE_GENDERS = {"male"}
MONTH_NAMES = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
]


# ==============================================================================
# SECTION 2: DATABASE CONNECTIONS, SECRET-KEY HASHING & SCHEMA MIGRATIONS
# ==============================================================================

# --- 2.1.1 Primary SQLite Connection Helper ---
VALID_ROLE_TABLES = {
    "students": "students",
    "teachers": "teachers",
    "admin": "admin",
}


def get_db_connection():
    """
    Opens database.db with Row access, 30s busy timeout, and foreign keys active.
    """
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


# --- 2.2.1 Secret-Key Password Hashing & Verification ---
def _derive_secret_salt(role_name):
    """Derives a role-scoped salt digest from Flask's app.secret_key."""
    secret = str(app.secret_key or "").encode("utf-8")
    role_bytes = str(role_name or "").strip().lower().encode("utf-8")
    return hashlib.sha256(secret + b"::" + role_bytes).hexdigest()


def _hash_password_with_secret(plain_password, role_name="user"):
    """
    Produces a Werkzeug PBKDF2-SHA256 hash over HMAC-SHA256(keyed_salt, password).
    """
    pw = (plain_password or "").strip()
    if not pw:
        return ""
    keyed_salt = _derive_secret_salt(role_name)
    peppered_material = hmac.new(
        keyed_salt.encode("utf-8"),
        pw.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return generate_password_hash(peppered_material, method="pbkdf2:sha256")


def _verify_password_with_secret(stored_hash, entered_password, role_name="user"):
    """Verifies entered_password against stored_hash using the active secret salt."""
    if not stored_hash or not entered_password:
        return False
    pw = entered_password.strip()
    keyed_salt = _derive_secret_salt(role_name)
    peppered_material = hmac.new(
        keyed_salt.encode("utf-8"),
        pw.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return check_password_hash(stored_hash, peppered_material)


# --- 2.2.2 Optional Plain-Text Password Mirror (plain_password.db) ---
def _get_plain_pass_conn():
    """Opens plain_password.db only when enabled and already present on disk."""
    if not ENABLE_PLAIN_PASS_SYNC or not os.path.exists(PLAIN_PASS_DB_PATH):
        return None
    pconn = sqlite3.connect(PLAIN_PASS_DB_PATH, timeout=15.0)
    pconn.row_factory = sqlite3.Row
    return pconn


def _save_password_everywhere(conn, role, user_id, username, plain_password):
    """
    Updates `password_hash` in `database.db` and mirrors plain text to
    `plain_password.db` when enabled and present.
    """
    table = VALID_ROLE_TABLES.get(role)
    if not table or not user_id or not plain_password:
        return ""

    pw_hash = _hash_password_with_secret(plain_password, role_name=role)
    conn.execute(
        f"UPDATE {table} SET password_hash = ? WHERE id = ?",
        (pw_hash, user_id),
    )

    pconn = _get_plain_pass_conn()
    if pconn:
        pconn.execute(f"""
            CREATE TABLE IF NOT EXISTS {table} (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                plain_password TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        pconn.execute(
            f"""
            INSERT INTO {table} (user_id, username, plain_password, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username,
                plain_password = excluded.plain_password,
                updated_at = excluded.updated_at
            """,
            (
                user_id,
                (username or "").strip(),
                plain_password,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        pconn.commit()
        pconn.close()

    return pw_hash


# --- 2.3.1 Individual Table & Column Ensurers ---
def _ensure_admin_table(conn):
    """Creates the `admin` table in database.db if missing."""
    conn.execute("""
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
    conn.commit()


def _ensure_fees_table(conn):
    """Creates the `fees` table and ensures audit/actor columns exist."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS fees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            month_year TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT DEFAULT 'Unpaid',
            payment_date TEXT,
            receipt_no TEXT,
            payment_mode TEXT DEFAULT 'Cash',
            updated_by TEXT DEFAULT '',
            updated_by_role TEXT DEFAULT '',
            updated_at TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES students (id) ON DELETE CASCADE
        )
    """)
    fee_cols = {row["name"] for row in conn.execute("PRAGMA table_info(fees)").fetchall()}
    for col_name, col_type in {
        "payment_mode": "TEXT DEFAULT 'Cash'",
        "updated_by": "TEXT DEFAULT ''",
        "updated_by_role": "TEXT DEFAULT ''",
        "updated_at": "TEXT DEFAULT ''",
        "created_at": "TEXT",
    }.items():
        if col_name not in fee_cols:
            conn.execute(f"ALTER TABLE fees ADD COLUMN {col_name} {col_type}")
    conn.commit()


def _ensure_profile_edit_requests_table(conn):
    """Creates the `profile_edit_requests` table in database.db if missing."""
    conn.execute("""
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
    conn.commit()


def _ensure_student_lifecycle_columns(conn):
    """Adds deactivated_at and leaving_reason columns to students if missing."""
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(students)").fetchall()}
    if "deactivated_at" not in cols:
        conn.execute("ALTER TABLE students ADD COLUMN deactivated_at TEXT")
    if "leaving_reason" not in cols:
        conn.execute("ALTER TABLE students ADD COLUMN leaving_reason TEXT")
    conn.commit()


def _ensure_extended_student_columns(conn):
    """Adds mother_name, panchayat, police_station, and pincode to students if missing."""
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(students)").fetchall()}
    for col_name, col_type in {
        "mother_name": "TEXT",
        "panchayat": "TEXT",
        "police_station": "TEXT",
        "pincode": "TEXT",
    }.items():
        if col_name not in cols:
            conn.execute(f"ALTER TABLE students ADD COLUMN {col_name} {col_type}")
    conn.commit()


def _ensure_student_approval_columns(conn):
    """Adds approved_by_teacher and approved_by_role audit columns to students."""
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(students)").fetchall()}
    if "approved_by_teacher" not in cols:
        conn.execute("ALTER TABLE students ADD COLUMN approved_by_teacher TEXT")
    if "approved_by_role" not in cols:
        conn.execute("ALTER TABLE students ADD COLUMN approved_by_role TEXT")
    conn.commit()


def _ensure_registered_by_columns(conn):
    """Ensures students table tracks which teacher registered each student."""
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(students)").fetchall()}
    if "registered_by_teacher" not in cols:
        conn.execute("ALTER TABLE students ADD COLUMN registered_by_teacher TEXT")
    if "registered_by_teacher_id" not in cols:
        conn.execute("ALTER TABLE students ADD COLUMN registered_by_teacher_id INTEGER")
    conn.commit()


def _ensure_attendance_table(conn):
    """Creates the `attendance` table and ensures `marked_by_teacher` exists."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            att_date TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Present',
            batch TEXT,
            remark TEXT,
            marked_by_teacher TEXT DEFAULT '',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(student_id, att_date),
            FOREIGN KEY (student_id) REFERENCES students (id) ON DELETE CASCADE
        )
    """)
    att_cols = {row["name"] for row in conn.execute("PRAGMA table_info(attendance)").fetchall()}
    if "marked_by_teacher" not in att_cols:
        conn.execute("ALTER TABLE attendance ADD COLUMN marked_by_teacher TEXT DEFAULT ''")
    conn.commit()


def _ensure_teachers_and_audit_tables(conn):
    """Creates `teachers` and `teacher_activity_log` and seeds a default teacher if empty."""
    conn.execute("""
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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS teacher_activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER,
            action_type TEXT NOT NULL,
            detail TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    existing_teacher = conn.execute("SELECT id FROM teachers LIMIT 1").fetchone()
    if not existing_teacher:
        default_t_pw = "Teacher@123"
        cur = conn.execute(
            """
            INSERT INTO teachers (username, password_hash, full_name, subject, phone, email, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "teacher",
                _hash_password_with_secret(default_t_pw, role_name="teachers"),
                "KM Campus Faculty",
                "Science & Maths",
                "",
                "faculty@kmcampus.local",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        _save_password_everywhere(conn, "teachers", cur.lastrowid, "teacher", default_t_pw)
    conn.commit()


# --- 2.3.2 Startup Database Bootstrapper ---
def init_db():
    """Initializes core tables, runs column migrations, and seeds initial admin."""
    conn = get_db_connection()
    cursor = conn.cursor()

    _ensure_admin_table(conn)

    cursor.execute("""
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
            registered_by_teacher TEXT,
            registered_by_teacher_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    _ensure_fees_table(conn)
    _ensure_profile_edit_requests_table(conn)
    _ensure_attendance_table(conn)
    _ensure_teachers_and_audit_tables(conn)

    cursor.execute("PRAGMA table_info(students)")
    student_cols = [col[1] for col in cursor.fetchall()]
    student_migrations = {
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
        "registered_by_teacher": "TEXT",
        "registered_by_teacher_id": "INTEGER",
    }
    for col_name, col_type in student_migrations.items():
        if col_name not in student_cols:
            cursor.execute(f"ALTER TABLE students ADD COLUMN {col_name} {col_type}")

    if not cursor.execute("SELECT id FROM admin LIMIT 1").fetchone():
        default_admin_user = os.environ.get("KM_ADMIN_USER", "Adarsh")
        default_admin_pw = os.environ.get("KM_ADMIN_PASS", "Adarsh@123")
        cursor.execute(
            """
            INSERT INTO admin (username, password_hash, full_name, email, phone, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                default_admin_user,
                _hash_password_with_secret(default_admin_pw, role_name="admin"),
                "Adarsh Sahani",
                "",
                "",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        _save_password_everywhere(conn, "admin", cursor.lastrowid, default_admin_user, default_admin_pw)

    conn.commit()
    conn.close()


init_db()


# ==============================================================================
# SECTION 3: PRIVACY MASKING & FRONTEND SANITIZATION LAYER
# ==============================================================================

# --- 3.1.1 Field-Level Masking Rules (Phone, Email, ID Number) ---
def _is_male_gender(gender):
    return (gender or "").strip().lower() in AUTHORISED_PHONE_GENDERS


def _is_female_gender(gender):
    return (gender or "").strip().lower() == "female"


def _mask_phone_for_frontend(phone, gender):
    """Discloses mobile numbers on standard views only for Male candidates."""
    raw = (phone or "").strip()
    if _is_male_gender(gender):
        return raw

    digits = "".join(ch for ch in raw if ch.isdigit())
    if len(digits) >= 3:
        return f"{digits[0]}{'*' * 7}{digits[-2:]}"
    if digits:
        return "*" * len(digits)
    return "Masked"


def _mask_email_for_frontend(email, gender):
    """Masks email addresses on standard views for Female candidates."""
    raw = (email or "").strip()
    if not raw:
        return ""
    if _is_female_gender(gender):
        if "@" in raw:
            local, domain = raw.split("@", 1)
            prefix = local[:1] if local else "*"
            return f"{prefix}***@{domain}"
        return "Hidden"
    return raw


def _mask_aadhaar_for_frontend(aadhaar):
    """Masks ID numbers to XXXX-XXXX-last4 on standard views."""
    raw = (aadhaar or "").strip()
    if not raw:
        return ""
    digits = "".join(ch for ch in raw if ch.isdigit())
    if len(digits) >= 4:
        return f"XXXX-XXXX-{digits[-4:]}"
    return "XXXX-XXXX-XXXX"


# --- 3.2.1 Row Sanitizers (Student, Teacher, Edit Request & Fee Views) ---
def _sanitize_student_for_frontend(student_obj, include_full_dossier=False):
    """Sanitizes student rows unless full unmasked admin dossier is requested."""
    data = {k: ("" if v is None else v) for k, v in dict(student_obj).items()}
    if include_full_dossier:
        return data

    gender = data.get("gender", "")
    data["phone"] = _mask_phone_for_frontend(data.get("phone", ""), gender)
    data["email"] = _mask_email_for_frontend(data.get("email", ""), gender)
    data["aadhaar"] = _mask_aadhaar_for_frontend(data.get("aadhaar", ""))
    return data


def _sanitize_student_for_teacher(row):
    """Masks phone and ID number for teacher views and hides direct ID doc paths."""
    raw = {k: ("" if v is None else v) for k, v in dict(row).items()}
    raw["phone"] = _mask_phone_for_frontend(raw.get("phone", ""), "female")
    raw["aadhaar"] = _mask_aadhaar_for_frontend(raw.get("aadhaar", ""))
    raw["aadhaar_doc"] = ""
    return raw


def _sanitize_edit_request_for_frontend(req_obj):
    """Masks sensitive fields in joined profile_edit_requests records."""
    data = {k: ("" if v is None else v) for k, v in dict(req_obj).items()}
    effective_gender = data.get("gender") or data.get("current_gender") or ""

    data["current_phone"] = _mask_phone_for_frontend(data.get("current_phone", ""), data.get("current_gender", ""))
    data["current_email"] = _mask_email_for_frontend(data.get("current_email", ""), data.get("current_gender", ""))
    data["current_aadhaar"] = _mask_aadhaar_for_frontend(data.get("current_aadhaar", ""))
    data["aadhaar"] = _mask_aadhaar_for_frontend(data.get("aadhaar", ""))
    data["gender_effective"] = effective_gender
    return data


def _sanitize_fee_row_for_frontend(fee_obj, include_receipt=True):
    """Normalizes fee rows for templates/JSON while keeping actor audit info clear."""
    data = {k: ("" if v is None else v) for k, v in dict(fee_obj).items()}
    actor = (data.get("updated_by") or "").strip()
    role = (data.get("updated_by_role") or "").strip()
    if actor:
        data["updated_by_display"] = f"{actor} ({role})" if role else actor
    else:
        data["updated_by_display"] = role.capitalize() if role else "System"
    if not include_receipt:
        data["receipt_no"] = ""
    return data


# ==============================================================================
# SECTION 4: AUTHENTICATION DECORATORS, TYPO SEARCH & SHARED HELPERS
# ==============================================================================

# --- 4.1.1 Multi-Role Session Guards (Student, Teacher, Admin) ---
def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("student_id"):
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function


def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("teacher_id"):
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function


# --- 4.2.1 Text, Batch & Request Helpers ---
def _format_gender_short(gender):
    g = (gender or "").strip().lower()
    if g == "male":
        return "M"
    if g == "female":
        return "F"
    return ""


def _clean_batch(raw_val, default_if_empty=""):
    val = (raw_val or "").replace("\u00a0", " ").strip()
    if not val or val.lower() in ("-- select batch --", "select batch", "none"):
        return default_if_empty
    return val


def _is_ajax_request():
    return (
        request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or request.args.get("ajax") == "1"
        or request.form.get("ajax") == "1"
    )


def _safe_float(val, default=0.0):
    try:
        if val is None or str(val).strip() == "":
            return default
        return float(val)
    except (ValueError, TypeError):
        return default


# --- 4.2.2 Upload Validation & Ranked Typo-Tolerant Search Engine ---
def _save_validated_upload(file_storage, prefix, allowed_exts, max_bytes, label):
    """Validates extension and byte size before saving into UPLOAD_FOLDER."""
    if not file_storage or not getattr(file_storage, "filename", ""):
        return "", None

    safe_orig = secure_filename(file_storage.filename)
    _, ext = os.path.splitext(safe_orig.lower())
    if ext not in allowed_exts:
        return "", f"{label} has an unsupported format ({ext or 'unknown'})."

    file_storage.stream.seek(0, os.SEEK_END)
    size_bytes = file_storage.stream.tell()
    file_storage.stream.seek(0)

    if size_bytes <= 0:
        return "", f"{label} file is empty."

    if size_bytes > max_bytes:
        max_kb = max_bytes // 1024
        actual_kb = round(size_bytes / 1024, 1)
        return "", f"{label} exceeds maximum allowed size of {max_kb} KB (file is {actual_kb} KB)."

    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    saved_name = secure_filename(f"{prefix}_{stamp}_{safe_orig}")
    file_storage.save(os.path.join(app.config["UPLOAD_FOLDER"], saved_name))
    return saved_name, None


def _rank_student_search_score(st_row, query_str):
    """
    Computes a relevance score (> 0 means matched) for typo-tolerant search across
    student name, username, father_name, phone, village, school_class, and batch.
    Exact/prefix/substring matches rank higher than fuzzy word-token typo matches.
    """
    q = (query_str or "").strip().lower()
    if not q:
        return 1.0

    row_keys = set(st_row.keys()) if hasattr(st_row, "keys") else set()

    def _get(col):
        return str(st_row[col] or "").strip() if col in row_keys else ""

    name_val = _get("name").lower()
    user_val = _get("username").lower()
    father_val = _get("father_name").lower()
    phone_val = _get("phone").lower()
    village_val = _get("village").lower()
    class_val = _get("school_class").lower()
    batch_val = _get("batch").lower()

    joined = " ".join(x for x in (name_val, user_val, father_val, phone_val, village_val, class_val, batch_val) if x)
    if not joined:
        return 0.0

    # Tier 1: Direct exact or prefix/substring match on primary identity fields
    if name_val == q or user_val == q:
        return 5.0
    if name_val.startswith(q) or user_val.startswith(q):
        return 4.2
    if q in name_val or q in user_val:
        return 3.5
    if q in joined:
        return 2.8

    # Tier 2: Multi-token and fuzzy typo matching per token
    q_tokens = [t for t in re.split(r"[\s@._-]+", q) if t]
    word_tokens = [w for w in re.split(r"[\s@._-]+", joined) if len(w) >= 2]
    if not q_tokens:
        return 0.0

    token_scores = []
    for qt in q_tokens:
        if qt in name_val or qt in user_val:
            token_scores.append(2.4)
            continue
        if qt in joined:
            token_scores.append(2.0)
            continue

        best_ratio = 0.0
        for wt in word_tokens:
            if abs(len(wt) - len(qt)) > max(2, len(qt) // 2 + 1):
                continue
            ratio = difflib.SequenceMatcher(None, qt, wt).ratio()
            if ratio > best_ratio:
                best_ratio = ratio

        # Also check prefix slice similarity for partial typos
        for field_txt in (name_val, user_val, father_val, village_val):
            if field_txt:
                slice_len = min(len(field_txt), max(len(qt), 3))
                s_ratio = difflib.SequenceMatcher(None, qt, field_txt[:slice_len]).ratio()
                if s_ratio > best_ratio:
                    best_ratio = s_ratio

        threshold = 0.60 if len(qt) <= 4 else 0.66
        if best_ratio >= threshold:
            token_scores.append(best_ratio * 1.6)
        else:
            return 0.0

    return round(sum(token_scores) / len(token_scores), 4)


def _is_typo_candidate(query_low, st_row):
    """Boolean wrapper around _rank_student_search_score for backward compatibility."""
    return _rank_student_search_score(st_row, query_low) > 0


def _fuzzy_student_fee_match(student_row, query_str):
    """Numeric relevance score (> 0 if matched) for student lookup and suggestions."""
    return _rank_student_search_score(student_row, query_str)


def _filter_and_rank_students(rows, query_str, key_fn=None):
    """Filters student rows using typo search and sorts with highest match score first."""
    q = (query_str or "").strip()
    if not q:
        return list(rows)

    scored = []
    for r in rows:
        score = _rank_student_search_score(r, q)
        if score > 0:
            sort_name = ""
            if key_fn:
                sort_name = str(key_fn(r) or "").lower()
            elif hasattr(r, "keys") and "name" in r.keys():
                sort_name = str(r["name"] or "").lower()
            scored.append((score, sort_name, r))

    scored.sort(key=lambda item: (-item[0], item[1]))
    return [item[2] for item in scored]


# --- 4.2.3 Audit Logging, Allowed Fee Window & PDF 1.4 Generator ---
def _log_teacher_activity(conn, teacher_id, action_type, detail):
    """Appends an entry to teacher_activity_log."""
    conn.execute(
        "INSERT INTO teacher_activity_log (teacher_id, action_type, detail, created_at) VALUES (?, ?, ?, ?)",
        (teacher_id, action_type, detail, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )


def _get_allowed_fee_periods(now):
    """Returns fee periods from -2 months through +4 months relative to `now`."""
    base_idx = now.year * 12 + (now.month - 1)
    periods = []
    for delta in range(-2, 5):
        target_idx = base_idx + delta
        yr = target_idx // 12
        mo_idx = target_idx % 12
        m_name = MONTH_NAMES[mo_idx]
        periods.append({
            "month": m_name,
            "year": str(yr),
            "label": f"{m_name} {yr}",
            "delta": delta,
        })
    return periods


def _generate_pdf_bytes(title, subtitle, pages_or_lines):
    """
    Generates a standalone multi-page PDF 1.4 byte stream without external libraries.
    Accepts either:
      - a list of strings (single page), OR
      - a list of (page_heading, page_sub, [lines...]) tuples (one or more pages).
    """
    def _esc(s):
        clean = "".join(ch if 32 <= ord(ch) <= 126 else "-" for ch in str(s))
        return clean.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    if pages_or_lines and isinstance(pages_or_lines[0], (tuple, list)):
        pages = pages_or_lines
    else:
        pages = [(title, subtitle, list(pages_or_lines or []))]

    font_size = 9.0
    line_step = 13.0
    max_lines_per_page = 54
    if len(pages) == 1 and len(pages[0][2]) > 42:
        font_size = 7.8
        line_step = 10.6
        max_lines_per_page = 66

    page_streams = []
    for p_title, p_sub, p_lines in pages:
        safe_lines = list(p_lines) if p_lines else ["No student records found."]
        chunks = [safe_lines[i : i + max_lines_per_page] for i in range(0, len(safe_lines), max_lines_per_page)]
        for idx_c, chunk in enumerate(chunks):
            hdr_title = p_title if idx_c == 0 else f"{p_title} (Cont.)"
            ops = [
                f"BT /F1 12.5 Tf 36 806 Td ({_esc(hdr_title)}) Tj ET",
                f"BT /F1 8.5 Tf 36 791 Td ({_esc(p_sub)}) Tj ET",
                "0.75 w 36 784 m 559 784 l S",
            ]
            y_pos = 768.0
            for line in chunk:
                ops.append(f"BT /F1 {font_size} Tf 36 {y_pos:.1f} Td ({_esc(line)}) Tj ET")
                y_pos -= line_step
            page_streams.append("\n".join(ops).encode("latin-1", errors="replace"))

    num_pages = len(page_streams)
    page_ids = [4 + i * 2 for i in range(num_pages)]
    kids_str = " ".join(f"{pid} 0 R" for pid in page_ids)

    objects = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
        f"2 0 obj << /Type /Pages /Kids [{kids_str}] /Count {num_pages} >> endobj\n".encode("latin-1"),
        b"3 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n",
    ]

    for i, s_bytes in enumerate(page_streams):
        pid = 4 + i * 2
        cid = 5 + i * 2
        page_obj = (
            f"{pid} 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {cid} 0 R >> endobj\n"
        ).encode("latin-1")
        content_obj = (
            f"{cid} 0 obj << /Length {len(s_bytes)} >> stream\n".encode("latin-1")
            + s_bytes
            + b"\nendstream endobj\n"
        )
        objects.append(page_obj)
        objects.append(content_obj)

    pdf_out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf_out))
        pdf_out.extend(obj)

    xref_pos = len(pdf_out)
    pdf_out.extend(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    pdf_out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        pdf_out.extend(f"{off:010d} 00000 n \n".encode("latin-1"))

    trailer = (
        f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n"
    ).encode("latin-1")
    pdf_out.extend(trailer)
    return bytes(pdf_out)


# --- 4.2.4 Fee Period, Payment Mode & Session Actor Helpers ---
def _resolve_fee_month_year(source_data, fallback_month, fallback_year):
    """Resolves `Month Year` from either `month_year`, `fee_period`, or `bill_month` + `bill_year`."""
    direct_my = (source_data.get("month_year") or "").strip()
    if direct_my:
        return direct_my

    raw_period = (source_data.get("fee_period") or "").strip()
    if raw_period:
        if len(raw_period) == 7 and raw_period[4] == "-" and raw_period[:4].isdigit() and raw_period[5:].isdigit():
            m_idx = int(raw_period[5:])
            if 1 <= m_idx <= 12:
                return f"{MONTH_NAMES[m_idx - 1]} {raw_period[:4]}"
        return raw_period

    b_month = (source_data.get("bill_month") or fallback_month).strip()
    if b_month.isdigit() and 1 <= int(b_month) <= 12:
        b_month = MONTH_NAMES[int(b_month) - 1]
    b_year = (source_data.get("bill_year") or fallback_year).strip()
    return f"{b_month} {b_year}".strip()


def _resolve_payment_mode(source_data):
    """Resolves payment mode including `custom_payment_mode` or `Other` selection."""
    custom_mode = (source_data.get("custom_payment_mode") or "").strip()
    chosen_mode = (source_data.get("payment_mode") or "Cash").strip()
    if chosen_mode.lower() == "other" and custom_mode:
        return custom_mode
    return custom_mode or chosen_mode or "Cash"


def _get_session_actor_info(role_key):
    """Returns `(actor_label, role_label)` for the active session user."""
    if role_key == "teacher":
        t_name = (session.get("teacher_name") or "Teacher").strip()
        t_user = (session.get("teacher_username") or "").strip()
        return (f"{t_name} (@{t_user})" if t_user else t_name), "Teacher"
    if role_key == "admin":
        a_user = (session.get("admin_user") or "Admin").strip()
        return a_user, "Admin"
    return "System", role_key.capitalize()


# --- 4.3.1 Shared Student Create & Direct Update Operations ---
def _create_student_record(conn, form_data, files_data, now, now_str, today_str):
    """Creates a student record and persists hashed + mirrored credentials."""
    name = (form_data.get("name") or "").strip()
    father_name = (form_data.get("father_name") or "").strip()
    mother_name = (form_data.get("mother_name") or "").strip()
    dob = (form_data.get("dob") or "").strip()
    gender = (form_data.get("gender") or "").strip()
    phone = (form_data.get("phone") or "").strip()
    aadhaar = (form_data.get("aadhaar") or "").strip()

    username = (form_data.get("username") or "").strip().lower()
    email = (form_data.get("email") or "").strip().lower()
    raw_password = (form_data.get("password") or "").strip()

    school_class = (form_data.get("school_class") or "").strip()
    batch = _clean_batch(form_data.get("batch"), default_if_empty="Morning Batch")

    country = (form_data.get("country") or "").strip()
    state = (form_data.get("state") or "").strip()
    district = (form_data.get("district") or "").strip()
    subdivision = (form_data.get("subdivision") or "").strip()
    block = (form_data.get("block") or "").strip()
    panchayat = (form_data.get("panchayat") or "").strip()
    village = (form_data.get("village") or "").strip()
    post = (form_data.get("post") or "").strip()
    police_station = (form_data.get("police_station") or "").strip()
    pincode = (form_data.get("pincode") or "").strip()

    initial_status = "Inactive" if (form_data.get("status") == "Inactive") else "Active"
    leaving_reason = (form_data.get("leaving_reason") or "").strip() if initial_status == "Inactive" else ""

    required_checks = [
        (name, "Student Name"),
        (father_name, "Father's Name"),
        (gender, "Gender"),
        (school_class, "Class"),
        (batch, "Batch"),
        (country, "Country"),
        (state, "State"),
        (district, "District"),
        (subdivision, "Subdivision"),
        (block, "Block"),
        (village, "Village"),
    ]
    missing_fields = [label for val, label in required_checks if not val]
    if missing_fields:
        return False, "Mandatory fields are empty: " + ", ".join(missing_fields) + ".", None
    if pincode and (not pincode.isdigit() or len(pincode) != 6):
        return False, "PIN Code must be a 6-digit numeric number.", None

    if not username:
        base_slug = "".join(ch.lower() for ch in name if ch.isalnum())[:12] or "student"
        username = f"{base_slug}_{now.strftime('%m%d%H%M')}"
    if conn.execute("SELECT id FROM students WHERE username = ?", (username,)).fetchone():
        username = f"{username}_{now.strftime('%S')}"

    if not email:
        email = f"{username}@kmcampus.local"
    if conn.execute("SELECT id FROM students WHERE email = ?", (email,)).fetchone():
        email = f"{username}_{random.randint(10, 99)}@kmcampus.local"

    plain_password = raw_password or (phone[-6:] if len(phone) >= 6 else "kmcampus123")
    hashed_password = _hash_password_with_secret(plain_password, role_name="students")
    deact_date = today_str if initial_status == "Inactive" else None

    photo = files_data.get("photo") if files_data else None
    aadhaar_doc = files_data.get("aadhaar_doc") if files_data else None

    photo_filename, photo_err = _save_validated_upload(
        photo, username, ALLOWED_PHOTO_EXTS, PHOTO_ACTUAL_MAX_BYTES, "Student Photo"
    )
    doc_filename, doc_err = _save_validated_upload(
        aadhaar_doc, f"{username}_doc", ALLOWED_AADHAAR_EXTS, AADHAAR_MAX_BYTES, "ID Document File"
    )
    file_errs = [e for e in (photo_err, doc_err) if e]
    if file_errs:
        return False, " ".join(file_errs), None

    cur = conn.execute(
        """
        INSERT INTO students (
            username, password_hash, email, name, father_name, mother_name,
            dob, gender, phone, aadhaar, batch, school_class,
            country, state, district, subdivision, block, panchayat,
            village, post, police_station, pincode,
            photo, aadhaar_doc, status, deactivated_at, leaving_reason, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            username, hashed_password, email, name, father_name, mother_name,
            dob, gender, phone, aadhaar, batch, school_class,
            country, state, district, subdivision, block, panchayat,
            village, post, police_station, pincode,
            photo_filename, doc_filename, initial_status, deact_date, leaving_reason, now_str,
        ),
    )
    new_id = cur.lastrowid
    _save_password_everywhere(conn, "students", new_id, username, plain_password)
    conn.commit()

    created_row = conn.execute("SELECT * FROM students WHERE id = ?", (new_id,)).fetchone()
    student_payload = _sanitize_student_for_frontend(created_row, include_full_dossier=False)
    student_payload["id"] = new_id
    msg = (
        f"Success! Student registered: {name} (S/o {father_name}) | Username: {username} | "
        f"Password: {plain_password} | Status: {initial_status}"
    )
    return True, msg, student_payload


def _apply_direct_student_edit(conn, student_id, form_data, files_data, today_str):
    """Updates an existing student record while preserving masked fields if left masked."""
    existing = conn.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
    if not existing:
        return False, "Student record not found.", None

    existing_dict = dict(existing)
    name = (form_data.get("name") or "").strip() or (existing_dict.get("name") or "").strip()
    father_name = (form_data.get("father_name") or "").strip() or (existing_dict.get("father_name") or "").strip()
    mother_name = (form_data.get("mother_name") or "").strip() if "mother_name" in form_data else (existing_dict.get("mother_name") or "").strip()
    dob = (form_data.get("dob") or "").strip() if "dob" in form_data else (existing_dict.get("dob") or "").strip()
    gender = (form_data.get("gender") or "").strip() or (existing_dict.get("gender") or "").strip()
    school_class = (form_data.get("school_class") or "").strip() or (existing_dict.get("school_class") or "").strip()
    batch = (
        _clean_batch(form_data.get("batch"), default_if_empty="")
        or _clean_batch(existing_dict.get("batch"), default_if_empty="Morning Batch")
    )

    phone = (form_data.get("phone") or "").strip() if "phone" in form_data else (existing_dict.get("phone") or "").strip()
    if phone and "*" in phone:
        phone = (existing_dict.get("phone") or "").strip()

    aadhaar = (form_data.get("aadhaar") or "").strip() if "aadhaar" in form_data else (existing_dict.get("aadhaar") or "").strip()
    if aadhaar and "XXXX" in aadhaar.upper():
        aadhaar = (existing_dict.get("aadhaar") or "").strip()

    username = (form_data.get("username") or "").strip().lower() or (existing_dict.get("username") or f"student_{student_id}")
    email = (form_data.get("email") or "").strip().lower() if "email" in form_data else (existing_dict.get("email") or "").strip().lower()
    if email and "***" in email:
        email = (existing_dict.get("email") or "").strip().lower()
    if not email:
        email = existing_dict.get("email") or ""

    new_password = (form_data.get("password") or "").strip()

    country = (form_data.get("country") or "").strip() if "country" in form_data else (existing_dict.get("country") or "").strip()
    state = (form_data.get("state") or "").strip() if "state" in form_data else (existing_dict.get("state") or "").strip()
    district = (form_data.get("district") or "").strip() if "district" in form_data else (existing_dict.get("district") or "").strip()
    subdivision = (form_data.get("subdivision") or "").strip() if "subdivision" in form_data else (existing_dict.get("subdivision") or "").strip()
    block = (form_data.get("block") or "").strip() if "block" in form_data else (existing_dict.get("block") or "").strip()
    panchayat = (form_data.get("panchayat") or "").strip() if "panchayat" in form_data else (existing_dict.get("panchayat") or "").strip()
    village = (form_data.get("village") or "").strip() if "village" in form_data else (existing_dict.get("village") or "").strip()
    post = (form_data.get("post") or "").strip() if "post" in form_data else (existing_dict.get("post") or "").strip()
    police_station = (form_data.get("police_station") or "").strip() if "police_station" in form_data else (existing_dict.get("police_station") or "").strip()
    pincode = (form_data.get("pincode") or "").strip() if "pincode" in form_data else (existing_dict.get("pincode") or "").strip()

    raw_status = (form_data.get("status") or "").strip()
    new_status = raw_status if raw_status in ("Active", "Inactive", "Pending") else (existing_dict.get("status") or "Active")
    leaving_reason = (form_data.get("leaving_reason") or "").strip() if "leaving_reason" in form_data else (existing_dict.get("leaving_reason") or "").strip()

    required_checks = [
        (name, "Student Name"),
        (father_name, "Father's Name"),
        (gender, "Gender"),
        (school_class, "Class"),
        (batch, "Batch"),
        (country, "Country"),
        (state, "State"),
        (district, "District"),
        (subdivision, "Subdivision"),
        (block, "Block"),
        (village, "Village"),
    ]
    missing_fields = [label for val, label in required_checks if not val]
    if missing_fields:
        return False, "Mandatory fields are empty: " + ", ".join(missing_fields) + ".", None
    if pincode and (not pincode.isdigit() or len(pincode) != 6):
        return False, "PIN Code must be a 6-digit numeric number.", None

    if conn.execute("SELECT id FROM students WHERE username = ? AND id != ?", (username, student_id)).fetchone():
        return False, f"Username '{username}' is already used by another student.", None

    if email and conn.execute("SELECT id FROM students WHERE email = ? AND id != ?", (email, student_id)).fetchone():
        return False, f"Email '{email}' is already used by another student.", None

    deact_date = existing_dict.get("deactivated_at")
    if new_status == "Inactive":
        deact_date = deact_date or today_str
    else:
        deact_date = None
        leaving_reason = ""

    photo = files_data.get("photo") if files_data else None
    aadhaar_doc = files_data.get("aadhaar_doc") if files_data else None

    photo_filename, photo_err = _save_validated_upload(
        photo, username, ALLOWED_PHOTO_EXTS, PHOTO_ACTUAL_MAX_BYTES, "Student Photo"
    )
    doc_filename, doc_err = _save_validated_upload(
        aadhaar_doc, f"{username}_doc", ALLOWED_AADHAAR_EXTS, AADHAAR_MAX_BYTES, "ID Document File"
    )
    file_errs = [e for e in (photo_err, doc_err) if e]
    if file_errs:
        return False, " ".join(file_errs), None

    final_photo = photo_filename or (existing_dict.get("photo") or "")
    final_doc = doc_filename or (existing_dict.get("aadhaar_doc") or "")

    conn.execute(
        """
        UPDATE students
        SET name = ?,
            father_name = ?,
            mother_name = ?,
            dob = ?,
            gender = ?,
            phone = ?,
            aadhaar = ?,
            username = ?,
            email = ?,
            school_class = ?,
            batch = ?,
            country = ?,
            state = ?,
            district = ?,
            subdivision = ?,
            block = ?,
            panchayat = ?,
            village = ?,
            post = ?,
            police_station = ?,
            pincode = ?,
            photo = ?,
            aadhaar_doc = ?,
            status = ?,
            deactivated_at = ?,
            leaving_reason = ?
        WHERE id = ?
        """,
        (
            name, father_name, mother_name, dob, gender, phone, aadhaar,
            username, email,
            school_class, batch,
            country, state, district, subdivision, block, panchayat,
            village, post, police_station, pincode,
            final_photo, final_doc,
            new_status, deact_date, leaving_reason, student_id,
        ),
    )
    if new_password:
        _save_password_everywhere(conn, "students", student_id, username, new_password)
    conn.commit()

    updated_row = conn.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
    safe_payload = _sanitize_student_for_frontend(updated_row, include_full_dossier=False)
    state_label = "Deactivated (Left)" if new_status == "Inactive" else new_status
    return True, f"Success! Updated details for {name} (Status: {state_label}).", safe_payload


# --- 4.3.2 Shared Fee Ledger & Suggestion Query Helpers ---
def _query_fee_student_suggestions(conn, query_text, batch_filter="", gender_filter="Both", class_filter="", limit=8):
    """Returns ranked active student suggestions (including typo matches) with current fee status."""
    q = (query_text or "").strip()
    if not q:
        return []

    now = datetime.now()
    lookup_period = f"{now.strftime('%B')} {now.year}"

    sql = """
        SELECT
            s.id AS student_id,
            s.name,
            s.father_name,
            s.username,
            s.school_class,
            s.batch,
            s.phone,
            s.email,
            s.aadhaar,
            s.gender,
            s.village,
            f.amount AS amount_paid,
            f.payment_date,
            f.receipt_no,
            COALESCE(f.payment_mode, 'Cash') AS payment_mode,
            COALESCE(f.updated_by, '') AS updated_by,
            CASE WHEN f.id IS NOT NULL AND f.status = 'Paid' THEN 'Paid' ELSE 'Unpaid' END AS fee_status
        FROM students s
        LEFT JOIN fees f ON s.id = f.student_id AND f.month_year = ?
        WHERE COALESCE(s.status, 'Active') = 'Active'
    """
    params = [lookup_period]

    if batch_filter:
        sql += " AND s.batch = ?"
        params.append(batch_filter)
    if gender_filter in ("Male", "Female"):
        sql += " AND LOWER(TRIM(COALESCE(s.gender, ''))) = ?"
        params.append(gender_filter.lower())
    if class_filter:
        sql += " AND TRIM(COALESCE(s.school_class, '')) = ?"
        params.append(class_filter)

    sql += " ORDER BY s.name ASC"
    candidates = conn.execute(sql, params).fetchall()

    q_low = q.lower()
    scored = []
    for st in candidates:
        score = _rank_student_search_score(st, q)
        if score <= 0:
            continue
        name_low = (st["name"] or "").lower()
        user_low = (st["username"] or "").lower()
        prefix_boost = 0.45 if (name_low.startswith(q_low) or user_low.startswith(q_low)) else 0.0
        scored.append((score + prefix_boost, (st["name"] or "").lower(), st))

    scored.sort(key=lambda item: (-item[0], item[1]))

    results = []
    for _, _, st in scored[:limit]:
        safe_st = _sanitize_student_for_frontend(st, include_full_dossier=False)
        gender_short = _format_gender_short(safe_st.get("gender"))
        phone_val = safe_st.get("phone") or "N/A"
        if gender_short != "M" and phone_val != "N/A" and len(phone_val) >= 3 and "*" not in phone_val:
            phone_val = f"{phone_val[:1]}*******{phone_val[-2:]}"

        results.append({
            "student_id": st["student_id"],
            "name": st["name"],
            "father_name": st["father_name"] or "N/A",
            "username": st["username"],
            "school_class": st["school_class"] or "N/A",
            "batch": st["batch"] or "Morning Batch",
            "village": st["village"] or "N/A",
            "phone_display": phone_val,
            "gender_short": gender_short,
            "fee_status": st["fee_status"],
            "amount_paid": st["amount_paid"] if st["amount_paid"] is not None else "",
            "payment_mode": st["payment_mode"] or "Cash",
            "updated_by": st["updated_by"] or "",
        })

    return results


def _build_fee_ledger_context(conn, *, role_key, flash_msg, allowed_fee_periods=None, print_all=False):
    """
    Shared builder for fee overview stats, typo-ranked student search, and monthly/yearly
    fee ledger rows used by both Admin and Teacher fee routes.
    """
    now = datetime.now()
    current_year_num = now.year
    current_month_num = now.month
    current_year = str(current_year_num)
    current_month_name = now.strftime("%B")
    month_to_idx = {m: idx + 1 for idx, m in enumerate(MONTH_NAMES)}

    raw_stat_month = (request.args.get("stat_month") or "").strip()
    if raw_stat_month == "Whole Year":
        stat_month = "Whole Year"
    elif raw_stat_month in MONTH_NAMES:
        stat_month = raw_stat_month
    else:
        stat_month = current_month_name

    stat_year = (request.args.get("stat_year") or "").strip() or current_year
    stat_period_label = f"Whole Year {stat_year}" if stat_month == "Whole Year" else f"{stat_month} {stat_year}"
    stat_year_int = int(stat_year) if stat_year.isdigit() else current_year_num
    stat_m_idx = month_to_idx.get(stat_month, current_month_num)

    batch_filter = (request.args.get("batch") or "").strip()
    gender_filter = (request.args.get("gender") or "Both").strip()
    if gender_filter not in ("Both", "Male", "Female"):
        gender_filter = "Both"
    class_filter = (request.args.get("school_class") or "").strip()
    status_filter = (request.args.get("status") or "All").strip()
    if status_filter not in ("All", "Paid", "Unpaid"):
        status_filter = "All"

    raw_month = (request.args.get("month") or "").strip()
    selected_year = (request.args.get("year") or "").strip() or stat_year
    if raw_month == "Whole Year":
        ledger_month_mode = "Whole Year"
        selected_month = f"Whole Year {selected_year}"
    elif raw_month in MONTH_NAMES:
        ledger_month_mode = raw_month
        selected_month = f"{raw_month} {selected_year}"
    else:
        ledger_month_mode = stat_month
        selected_month = (
            f"{ledger_month_mode} {selected_year}"
            if ledger_month_mode != "Whole Year"
            else f"Whole Year {selected_year}"
        )

    search_query = (request.args.get("q") or "").strip()
    ledger_searched = (request.args.get("ledger_search") or "").strip() == "1"
    year_options = [str(y) for y in range(current_year_num - 2, current_year_num + 4)]

    batch_rows = conn.execute(
        "SELECT DISTINCT batch FROM students WHERE COALESCE(status, 'Active') = 'Active' AND batch IS NOT NULL AND TRIM(batch) != '' ORDER BY batch ASC"
    ).fetchall()
    batch_options = [r["batch"].strip() for r in batch_rows] or ["Morning Batch", "Evening Batch"]

    class_rows = conn.execute(
        "SELECT DISTINCT TRIM(school_class) AS sc FROM students WHERE COALESCE(status, 'Active') = 'Active' AND school_class IS NOT NULL AND TRIM(school_class) != '' ORDER BY sc ASC"
    ).fetchall()
    class_options = [r["sc"] for r in class_rows]

    raw_all_students = conn.execute(
        "SELECT id, name, username, school_class, batch, phone, email, aadhaar, gender FROM students WHERE COALESCE(status, 'Active') = 'Active' ORDER BY name ASC"
    ).fetchall()
    all_students = []
    for st in raw_all_students:
        st_dict = _sanitize_student_for_frontend(st, include_full_dossier=False)
        st_dict["gender_short"] = _format_gender_short(st_dict.get("gender"))
        all_students.append(st_dict)

    searched_students = []
    search_triggered = bool(search_query)
    if search_triggered:
        lookup_period = f"{stat_month if stat_month != 'Whole Year' else current_month_name} {stat_year}"
        raw_candidates = conn.execute(
            """
            SELECT
                s.id AS student_id,
                s.name,
                s.father_name,
                s.username,
                s.school_class,
                s.batch,
                s.phone,
                s.email,
                s.aadhaar,
                s.gender,
                s.village,
                f.amount AS amount_paid,
                f.payment_date,
                f.receipt_no,
                COALESCE(f.payment_mode, 'Cash') AS payment_mode,
                COALESCE(f.updated_by, '') AS updated_by,
                CASE WHEN f.id IS NOT NULL AND f.status = 'Paid' THEN 'Paid' ELSE 'Unpaid' END AS fee_status
            FROM students s
            LEFT JOIN fees f ON s.id = f.student_id AND f.month_year = ?
            WHERE COALESCE(s.status, 'Active') = 'Active'
            ORDER BY s.name ASC
            """,
            (lookup_period,),
        ).fetchall()

        ranked_matches = _filter_and_rank_students(raw_candidates, search_query)
        for st in ranked_matches:
            st_dict = _sanitize_student_for_frontend(st, include_full_dossier=False)
            st_dict["gender_short"] = _format_gender_short(st_dict.get("gender"))
            st_dict["updated_by"] = st["updated_by"]
            searched_students.append(st_dict)

    stat_student_sql = "SELECT id AS student_id, batch FROM students WHERE COALESCE(status, 'Active') = 'Active'"
    stat_student_params = []
    if batch_filter:
        stat_student_sql += " AND batch = ?"
        stat_student_params.append(batch_filter)
    if gender_filter in ("Male", "Female"):
        stat_student_sql += " AND LOWER(TRIM(COALESCE(gender, ''))) = ?"
        stat_student_params.append(gender_filter.lower())
    if class_filter:
        stat_student_sql += " AND TRIM(COALESCE(school_class, '')) = ?"
        stat_student_params.append(class_filter)

    stat_students = conn.execute(stat_student_sql, stat_student_params).fetchall()
    total_batch_students = len(stat_students)
    allowed_stat_ids = {st["student_id"] for st in stat_students}

    stat_year_fees = conn.execute(
        "SELECT student_id, month_year, amount, status FROM fees WHERE month_year LIKE ?",
        (f"% {stat_year}",),
    ).fetchall()

    stat_fees_by_student_month = {}
    stat_first_paid_idx = {}
    for fr in stat_year_fees:
        if fr["student_id"] not in allowed_stat_ids:
            continue
        m_name = (fr["month_year"] or "").replace(f" {stat_year}", "").strip()
        m_idx = month_to_idx.get(m_name)
        if m_idx and fr["status"] == "Paid":
            stat_fees_by_student_month[(fr["student_id"], m_idx)] = fr["amount"]
            prev = stat_first_paid_idx.get(fr["student_id"])
            if prev is None or m_idx < prev:
                stat_first_paid_idx[fr["student_id"]] = m_idx

    paid_count = 0
    unpaid_count = 0
    total_collected = 0.0

    if stat_month == "Whole Year":
        for fr in stat_year_fees:
            if fr["student_id"] not in allowed_stat_ids:
                continue
            m_name = (fr["month_year"] or "").replace(f" {stat_year}", "").strip()
            if m_name in month_to_idx and fr["status"] == "Paid":
                total_collected += _safe_float(fr["amount"], 0.0)

        max_billed_idx = 12 if stat_year_int < current_year_num else (current_month_num if stat_year_int == current_year_num else 0)
        for st in stat_students:
            sid = st["student_id"]
            first_idx = stat_first_paid_idx.get(sid)
            has_any_paid = first_idx is not None
            has_unpaid_in_year = False
            for m_i in range(1, max_billed_idx + 1):
                if (sid, m_i) not in stat_fees_by_student_month:
                    if first_idx is not None and m_i < first_idx:
                        continue
                    has_unpaid_in_year = True
                    break

            if has_any_paid and not has_unpaid_in_year:
                paid_count += 1
            elif has_unpaid_in_year:
                unpaid_count += 1
    else:
        for st in stat_students:
            sid = st["student_id"]
            amt = stat_fees_by_student_month.get((sid, stat_m_idx))
            if amt is not None:
                paid_count += 1
                total_collected += _safe_float(amt, 0.0)
            else:
                first_idx = stat_first_paid_idx.get(sid)
                is_upcoming = (
                    stat_year_int > current_year_num
                    or (stat_year_int == current_year_num and stat_m_idx > current_month_num)
                )
                if not ((first_idx is not None and stat_m_idx < first_idx) or is_upcoming):
                    unpaid_count += 1

    display_rows = []
    ledger_total_collected = 0.0

    if ledger_searched:
        student_sql = """
            SELECT
                s.id AS student_id, s.name, s.username, s.school_class, s.batch,
                s.phone, s.email, s.aadhaar, s.gender
            FROM students s
            WHERE COALESCE(s.status, 'Active') = 'Active'
        """
        student_params = []
        if batch_filter:
            student_sql += " AND s.batch = ?"
            student_params.append(batch_filter)
        if gender_filter in ("Male", "Female"):
            student_sql += " AND LOWER(TRIM(COALESCE(s.gender, ''))) = ?"
            student_params.append(gender_filter.lower())
        if class_filter:
            student_sql += " AND TRIM(COALESCE(s.school_class, '')) = ?"
            student_params.append(class_filter)
        student_sql += " ORDER BY s.name ASC"
        base_students = conn.execute(student_sql, student_params).fetchall()

        year_fee_rows = conn.execute(
            """
            SELECT student_id, month_year, amount, payment_date, receipt_no,
                   COALESCE(payment_mode, 'Cash') AS payment_mode,
                   COALESCE(updated_by, '') AS updated_by, status
            FROM fees
            WHERE month_year LIKE ?
            """,
            (f"% {selected_year}",),
        ).fetchall()

        fees_by_student_month = {}
        first_paid_idx_by_student = {}
        for fr in year_fee_rows:
            m_name = (fr["month_year"] or "").replace(f" {selected_year}", "").strip()
            m_idx = month_to_idx.get(m_name)
            if m_idx and fr["status"] == "Paid":
                fees_by_student_month[(fr["student_id"], m_idx)] = dict(fr)
                prev_first = first_paid_idx_by_student.get(fr["student_id"])
                if prev_first is None or m_idx < prev_first:
                    first_paid_idx_by_student[fr["student_id"]] = m_idx

        selected_year_int = int(selected_year) if selected_year.isdigit() else current_year_num

        def classify_month_status(sid, m_idx):
            fee_rec = fees_by_student_month.get((sid, m_idx))
            if fee_rec:
                return {
                    "month": MONTH_NAMES[m_idx - 1],
                    "short": MONTH_NAMES[m_idx - 1][:3],
                    "code": "Paid",
                    "label": f"Paid ₹{fee_rec['amount']}",
                    "short_label": f"₹{fee_rec['amount']}",
                    "amount": fee_rec["amount"],
                    "payment_date": fee_rec["payment_date"],
                    "receipt_no": fee_rec["receipt_no"],
                    "payment_mode": fee_rec["payment_mode"],
                    "updated_by": fee_rec.get("updated_by") or "",
                }

            first_paid_idx = first_paid_idx_by_student.get(sid)
            if first_paid_idx is not None and m_idx < first_paid_idx:
                return {
                    "month": MONTH_NAMES[m_idx - 1],
                    "short": MONTH_NAMES[m_idx - 1][:3],
                    "code": "BeforeFirstFee",
                    "label": "Pre-First Fee",
                    "short_label": "Pre",
                    "amount": None,
                    "payment_date": None,
                    "receipt_no": None,
                    "payment_mode": None,
                    "updated_by": "",
                }

            is_upcoming = (
                selected_year_int > current_year_num
                or (selected_year_int == current_year_num and m_idx > current_month_num)
            )
            if is_upcoming:
                return {
                    "month": MONTH_NAMES[m_idx - 1],
                    "short": MONTH_NAMES[m_idx - 1][:3],
                    "code": "Upcoming",
                    "label": "Upcoming Month",
                    "short_label": "Upc",
                    "amount": None,
                    "payment_date": None,
                    "receipt_no": None,
                    "payment_mode": None,
                    "updated_by": "",
                }

            return {
                "month": MONTH_NAMES[m_idx - 1],
                "short": MONTH_NAMES[m_idx - 1][:3],
                "code": "Unpaid",
                "label": "Not Paid",
                "short_label": "Due",
                "amount": None,
                "payment_date": None,
                "receipt_no": None,
                "payment_mode": None,
                "updated_by": "",
            }

        ledger_entries = []
        if ledger_month_mode == "Whole Year":
            for st in base_students:
                safe_st = _sanitize_student_for_frontend(st, include_full_dossier=False)
                monthly_breakdown = [classify_month_status(st["student_id"], idx) for idx in range(1, 13)]
                st_paid = [m for m in monthly_breakdown if m["code"] == "Paid"]
                st_unpaid = [m for m in monthly_breakdown if m["code"] == "Unpaid"]
                st_upcoming = [m for m in monthly_breakdown if m["code"] == "Upcoming"]
                st_pre = [m for m in monthly_breakdown if m["code"] == "BeforeFirstFee"]

                st_total = sum(_safe_float(pm["amount"], 0.0) for pm in st_paid)
                ledger_total_collected += st_total

                if len(st_unpaid) == 0 and len(st_paid) > 0:
                    overall_badge = f"Cleared ({len(st_paid)} Paid)"
                elif len(st_unpaid) > 0:
                    overall_badge = f"{len(st_unpaid)} Not Paid"
                else:
                    overall_badge = f"{len(st_upcoming)} Upcoming"

                ledger_entries.append({
                    "student_id": st["student_id"],
                    "name": st["name"],
                    "username": st["username"],
                    "school_class": st["school_class"],
                    "batch": st["batch"],
                    "gender_short": _format_gender_short(st["gender"]),
                    "phone": safe_st["phone"],
                    "email": safe_st["email"],
                    "aadhaar": safe_st["aadhaar"],
                    "overall_badge": overall_badge,
                    "year_total": st_total,
                    "paid_months_count": len(st_paid),
                    "unpaid_months_count": len(st_unpaid),
                    "upcoming_months_count": len(st_upcoming),
                    "pre_months_count": len(st_pre),
                    "monthly_breakdown": monthly_breakdown,
                })
        else:
            target_m_idx = month_to_idx.get(ledger_month_mode, current_month_num)
            for st in base_students:
                safe_st = _sanitize_student_for_frontend(st, include_full_dossier=False)
                m_info = classify_month_status(st["student_id"], target_m_idx)
                if m_info["code"] == "Paid":
                    ledger_total_collected += _safe_float(m_info["amount"], 0.0)

                ledger_entries.append({
                    "student_id": st["student_id"],
                    "name": st["name"],
                    "username": st["username"],
                    "school_class": st["school_class"],
                    "batch": st["batch"],
                    "gender_short": _format_gender_short(st["gender"]),
                    "phone": safe_st["phone"],
                    "email": safe_st["email"],
                    "aadhaar": safe_st["aadhaar"],
                    "month_status_code": m_info["code"],
                    "month_status_label": m_info["label"],
                    "amount_paid": m_info["amount"],
                    "payment_date": m_info["payment_date"],
                    "receipt_no": m_info["receipt_no"],
                    "payment_mode": m_info["payment_mode"],
                    "updated_by": m_info["updated_by"],
                })

        if status_filter == "Paid":
            display_rows = (
                [e for e in ledger_entries if e["paid_months_count"] > 0 and e["unpaid_months_count"] == 0]
                if ledger_month_mode == "Whole Year"
                else [e for e in ledger_entries if e["month_status_code"] == "Paid"]
            )
        elif status_filter == "Unpaid":
            display_rows = (
                [e for e in ledger_entries if e["unpaid_months_count"] > 0]
                if ledger_month_mode == "Whole Year"
                else [e for e in ledger_entries if e["month_status_code"] != "Paid"]
            )
        else:
            display_rows = ledger_entries

    ctx = {
        "stat_month": stat_month,
        "stat_year": stat_year,
        "stat_period_label": stat_period_label,
        "selected_month": selected_month,
        "ledger_month_mode": ledger_month_mode,
        "selected_year": selected_year,
        "current_year": current_year,
        "current_month_name": current_month_name,
        "year_options": year_options,
        "month_options": MONTH_NAMES,
        "batch_options": batch_options,
        "class_options": class_options,
        "batch_filter": batch_filter,
        "gender_filter": gender_filter,
        "class_filter": class_filter,
        "status_filter": status_filter,
        "search_query": search_query,
        "student_q": search_query,
        "search_triggered": search_triggered,
        "ledger_searched": ledger_searched,
        "searched_students": searched_students,
        "all_students": all_students,
        "rows": display_rows,
        "paid_count": paid_count,
        "unpaid_count": unpaid_count,
        "total_students": total_batch_students,
        "total_collected": total_collected,
        "ledger_total_collected": ledger_total_collected,
        "today_date": now.strftime("%Y-%m-%d"),
        "flash_msg": flash_msg,
        "allowed_fee_periods": allowed_fee_periods or [],
        "print_all": bool(print_all),
    }

    if role_key == "teacher":
        t_name = session.get("teacher_name", "Teacher")
        t_user = session.get("teacher_username", "")
        ctx["teacher_name"] = t_name
        ctx["teacher_username"] = t_user
        ctx["current_teacher_name"] = t_name

    return ctx

# ==============================================================================
# SECTION 5: PUBLIC PORTAL, OTP VERIFICATION & STUDENT REGISTRATION ROUTES
# ==============================================================================

# --- 5.1.1 Portal Home & Registration OTP Endpoints ---
@app.route("/")
def index():
    """Renders the multi-role sign-in portal."""
    return render_template("common/index.html")


@app.route("/send-reg-otp", methods=["POST"])
def send_reg_otp():
    """Generates and stores a 6-digit registration OTP in the session."""
    email = request.form.get("email", "").strip().lower()
    if not email:
        return jsonify({"status": "error", "message": "Email address is required."})

    otp = str(random.randint(100000, 999999))
    session["reg_otp"] = otp
    session["reg_otp_email"] = email
    session["otp_verified"] = False

    print(f"[OTP DEBUG LOG] Registration OTP for {email}: {otp} (Common Testing OTP: 032002)")
    return jsonify({"status": "success"})


@app.route("/verify-reg-otp", methods=["POST"])
def verify_reg_otp():
    """Validates the submitted registration OTP against session state."""
    entered_otp = request.form.get("otp", "").strip()
    stored_otp = session.get("reg_otp")

    if entered_otp == "032002" or (stored_otp and entered_otp == stored_otp):
        session["otp_verified"] = True
        return jsonify({"status": "verified", "message": "Email successfully verified!"})

    return jsonify({"status": "error", "message": "Invalid OTP. Please check and try again."})


# --- 5.2.1 Two-Step Student Self-Registration Flow ---
@app.route("/register", methods=["GET", "POST"])
def register_step1():
    """Step 1: Validates credentials and email OTP before moving to Step 2."""
    if request.method == "POST":
        form_data = dict(request.form)
        username = form_data.get("username", "").strip().lower()
        email = form_data.get("email", "").strip().lower()

        if not session.get("otp_verified") or session.get("reg_otp_email") != email:
            return render_template(
                "student/register_step1.html",
                error="⚠️ You must verify your email address with the OTP before proceeding.",
                form_data=form_data,
            )

        conn = get_db_connection()
        if conn.execute("SELECT id FROM students WHERE username = ?", (username,)).fetchone():
            conn.close()
            suggested_username = f"{username}{random.randint(10, 99)}"
            return render_template(
                "student/register_step1.html",
                error=f"Username already taken. Try a unique suggestion like '{suggested_username}'.",
                form_data=form_data,
            )

        if conn.execute("SELECT id FROM students WHERE email = ?", (email,)).fetchone():
            conn.close()
            return render_template(
                "student/register_step1.html",
                error="This email address is already registered.",
                form_data=form_data,
            )
        conn.close()

        session["reg_step1"] = form_data
        session.pop("reg_otp", None)
        session.pop("reg_otp_email", None)
        session.pop("otp_verified", None)
        return redirect(url_for("register_step2"))

    return render_template("student/register_step1.html", form_data=session.get("reg_step1", {}))


@app.route("/register/step2", methods=["GET", "POST"])
def register_step2():
    """Step 2: Saves profile, address, and document uploads with Pending status."""
    if "reg_step1" not in session:
        return redirect(url_for("register_step1"))

    if request.method == "POST":
        step1 = session.get("reg_step1", {})
        username_slug = (step1.get("username") or "student").strip().lower()
        email_clean = (step1.get("email") or "").strip().lower()
        plain_pw = (step1.get("password") or "").strip()
        hashed_pw = _hash_password_with_secret(plain_pw, role_name="students")

        photo_filename, photo_err = _save_validated_upload(
            request.files.get("photo"),
            username_slug,
            ALLOWED_PHOTO_EXTS,
            PHOTO_ACTUAL_MAX_BYTES,
            "Student Photo",
        )
        doc_filename, doc_err = _save_validated_upload(
            request.files.get("aadhaar_doc"),
            f"{username_slug}_doc",
            ALLOWED_AADHAAR_EXTS,
            AADHAAR_MAX_BYTES,
            "ID Document File",
        )
        file_errs = [e for e in (photo_err, doc_err) if e]
        if file_errs:
            return render_template("student/register_step2.html", error=" ".join(file_errs))

        def _pick_location(field_name):
            val = request.form.get(field_name)
            return request.form.get(f"{field_name}_manual", "").strip() if val == "Other" else val

        conn = get_db_connection()
        try:
            _ensure_extended_student_columns(conn)
            cur = conn.execute(
                """
                INSERT INTO students (
                    name, father_name, mother_name, email, phone,
                    village, post, police_station, panchayat, pincode,
                    username, password_hash, dob, gender, batch, school_class,
                    country, state, district, subdivision, block, aadhaar,
                    photo, aadhaar_doc, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending')
                """,
                (
                    (step1.get("name") or "").strip(),
                    (step1.get("father_name") or "").strip(),
                    (request.form.get("mother_name") or step1.get("mother_name") or "").strip(),
                    email_clean,
                    (step1.get("phone") or "").strip(),
                    (request.form.get("village") or "").strip(),
                    (request.form.get("post") or "").strip(),
                    (request.form.get("police_station") or "").strip(),
                    (request.form.get("panchayat") or "").strip(),
                    (request.form.get("pincode") or "").strip(),
                    username_slug,
                    hashed_pw,
                    (step1.get("dob") or "").strip(),
                    (request.form.get("gender") or "").strip(),
                    step1.get("batch", "Morning Batch"),
                    (step1.get("school_class") or "").strip(),
                    _pick_location("country"),
                    _pick_location("state"),
                    _pick_location("district"),
                    _pick_location("subdivision"),
                    _pick_location("block"),
                    (request.form.get("aadhaar") or "").strip(),
                    photo_filename,
                    doc_filename,
                ),
            )
            _save_password_everywhere(conn, "students", cur.lastrowid, username_slug, plain_pw)
            conn.commit()
        except Exception as exc:
            app.logger.exception("Student registration step2 failed")
            conn.close()
            return render_template("student/register_step2.html", error=f"Database insertion error: {exc}")
        finally:
            conn.close()

        session.pop("reg_step1", None)
        return render_template("student/register_success.html", name=step1.get("name"))

    return render_template("student/register_step2.html")


# ==============================================================================
# SECTION 6: STUDENT PORTAL ROUTES (AUTH, DASHBOARD & FEE LEDGER)
# ==============================================================================

# --- 6.1.1 Student Authentication & Session Cleanup ---
@app.route("/student-login", methods=["POST"])
def student_login():
    """Authenticates a student against stored password_hash."""
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "").strip()

    conn = get_db_connection()
    student = conn.execute(
        "SELECT * FROM students WHERE LOWER(username) = ? OR LOWER(email) = ?",
        (username, username),
    ).fetchone()
    conn.close()

    if student and _verify_password_with_secret(student["password_hash"], password, role_name="students"):
        session["student_id"] = student["id"]
        session["student_name"] = student["name"]
        return redirect(url_for("student_dashboard"))

    return render_template("common/index.html", error="Invalid username or password.")


@app.route("/student-logout")
def student_logout():
    """Clears student session keys only."""
    session.pop("student_id", None)
    session.pop("student_name", None)
    return redirect(url_for("index"))


# --- 6.2.1 Student Dashboard & Fee Ledger Views ---
@app.route("/student-dashboard")
@student_required
def student_dashboard():
    """Renders student dashboard with profile completion and fee history."""
    conn = get_db_connection()
    _ensure_fees_table(conn)
    raw_student = conn.execute("SELECT * FROM students WHERE id = ?", (session["student_id"],)).fetchone()
    fee_history = conn.execute(
        "SELECT * FROM fees WHERE student_id = ? ORDER BY id DESC",
        (session["student_id"],),
    ).fetchall()
    conn.close()

    if not raw_student:
        return redirect(url_for("student_logout"))

    tracked_fields = [
        raw_student["name"], raw_student["father_name"], raw_student["dob"], raw_student["gender"],
        raw_student["phone"], raw_student["aadhaar"], raw_student["village"], raw_student["district"],
        raw_student["photo"], raw_student["aadhaar_doc"],
    ]
    filled_count = sum(1 for val in tracked_fields if val and str(val).strip())
    completion_percentage = int((filled_count / len(tracked_fields)) * 100)

    safe_student = _sanitize_student_for_frontend(raw_student, include_full_dossier=False)
    return render_template(
        "student/student_dashboard.html",
        student=safe_student,
        fee_history=fee_history,
        completion_percentage=completion_percentage,
    )


@app.route("/student/fees")
@student_required
def student_fee_ledger():
    """Renders the student's fee ledger and total paid amount."""
    conn = get_db_connection()
    _ensure_fees_table(conn)
    raw_student = conn.execute("SELECT * FROM students WHERE id = ?", (session["student_id"],)).fetchone()
    fees = conn.execute(
        "SELECT * FROM fees WHERE student_id = ? ORDER BY id DESC",
        (session["student_id"],),
    ).fetchall()
    conn.close()

    total_paid = sum(_safe_float(f["amount"], 0.0) for f in fees)
    safe_student = _sanitize_student_for_frontend(raw_student, include_full_dossier=False) if raw_student else None
    return render_template(
        "student/fee_ledger.html",
        student=safe_student,
        fees=fees,
        total_paid=total_paid,
    )


# ==============================================================================
# SECTION 7: ADMIN CORE ROUTES (AUTH, PROFILE, DASHBOARD, SEARCH & DOSSIER)
# ==============================================================================

# --- 7.1.1 Admin Authentication & Profile Management ---
@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    """Authenticates administrator against `admin.password_hash` in database.db."""
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "").strip()

        conn = get_db_connection()
        _ensure_admin_table(conn)
        admin_row = conn.execute(
            "SELECT * FROM admin WHERE LOWER(username) = ?",
            (username,),
        ).fetchone()
        conn.close()

        if admin_row and _verify_password_with_secret(admin_row["password_hash"], password, role_name="admin"):
            session["admin_logged_in"] = True
            session["admin_id"] = admin_row["id"]
            session["admin_user"] = admin_row["username"]
            return redirect(url_for("admin_dashboard"))

        return render_template("common/index.html", error="Invalid Admin Credentials.")

    return render_template("admin/admin_login.html")


@app.route("/admin/profile", methods=["GET", "POST"])
@admin_required
def admin_profile():
    """Updates admin account info and password in SQLite."""
    conn = get_db_connection()
    _ensure_admin_table(conn)
    admin_row = conn.execute(
        "SELECT * FROM admin WHERE id = ? OR LOWER(username) = LOWER(?) ORDER BY id ASC LIMIT 1",
        (session.get("admin_id") or 0, session.get("admin_user") or ""),
    ).fetchone()

    msg = ""
    ok = False
    if request.method == "POST" and admin_row:
        new_username = (request.form.get("username") or admin_row["username"]).strip()
        full_name = (request.form.get("full_name") or admin_row["full_name"]).strip()
        email = (request.form.get("email") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        new_password = (request.form.get("new_password") or "").strip()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conflict = conn.execute(
            "SELECT id FROM admin WHERE LOWER(username) = LOWER(?) AND id != ?",
            (new_username, admin_row["id"]),
        ).fetchone()
        if not new_username:
            msg = "Admin username cannot be empty."
        elif conflict:
            msg = f"Username '{new_username}' is already taken."
        else:
            conn.execute(
                """
                UPDATE admin
                SET username = ?, full_name = ?, email = ?, phone = ?, updated_at = ?
                WHERE id = ?
                """,
                (new_username, full_name, email, phone, now_str, admin_row["id"]),
            )
            if new_password:
                _save_password_everywhere(conn, "admin", admin_row["id"], new_username, new_password)
            conn.commit()
            session["admin_id"] = admin_row["id"]
            session["admin_user"] = new_username
            admin_row = conn.execute("SELECT * FROM admin WHERE id = ?", (admin_row["id"],)).fetchone()
            msg = "Admin profile updated successfully."
            ok = True

    conn.close()
    return render_template(
        "admin/admin_profile.html",
        admin_info=dict(admin_row) if admin_row else {},
        msg=msg,
        ok=ok,
    )


@app.route("/admin-logout")
def admin_logout():
    """Clears administrator session keys only."""
    session.pop("admin_logged_in", None)
    session.pop("admin_id", None)
    session.pop("admin_user", None)
    return redirect(url_for("index"))


# --- 7.2.1 Admin Dashboard, Ranked Typo Search & Student Dossier ---
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    """Renders the admin control center with summary counts."""
    conn = get_db_connection()
    _ensure_fees_table(conn)
    _ensure_profile_edit_requests_table(conn)

    pending_reg_count = conn.execute("SELECT COUNT(*) FROM students WHERE status = 'Pending'").fetchone()[0]
    pending_edit_count = conn.execute("SELECT COUNT(*) FROM profile_edit_requests WHERE status = 'Pending'").fetchone()[0]
    active_count = conn.execute("SELECT COUNT(*) FROM students WHERE status = 'Active'").fetchone()[0]
    enrolled_count = conn.execute("SELECT COUNT(*) FROM students WHERE COALESCE(status, 'Active') != 'Pending'").fetchone()[0]

    current_month_str = datetime.now().strftime("%B %Y")
    total_paid = conn.execute(
        "SELECT COUNT(*) FROM fees WHERE month_year = ? AND status = 'Paid'",
        (current_month_str,),
    ).fetchone()[0]
    total_unpaid = max(0, active_count - total_paid)
    conn.close()

    return render_template(
        "admin/dashboard.html",
        pending_reg_count=pending_reg_count,
        pending_edit_count=pending_edit_count,
        active_count=active_count,
        enrolled_count=enrolled_count,
        total_paid=total_paid,
        total_unpaid=total_unpaid,
        current_month=current_month_str,
    )


@app.route("/admin-search")
@admin_required
def admin_search():
    """Performs ranked typo-tolerant search across student records with top matches first."""
    query = request.args.get("q", "").strip()
    current_month_str = datetime.now().strftime("%B %Y")

    conn = get_db_connection()
    _ensure_fees_table(conn)
    raw_candidates = conn.execute(
        """
        SELECT s.*, COALESCE(f.status, 'Unpaid') AS fee_status
        FROM students s
        LEFT JOIN fees f ON s.id = f.student_id AND f.month_year = ?
        ORDER BY s.name ASC
        """,
        (current_month_str,),
    ).fetchall()
    conn.close()

    ranked_rows = _filter_and_rank_students(raw_candidates, query)
    results = [_sanitize_student_for_frontend(r, include_full_dossier=False) for r in ranked_rows]
    return render_template(
        "admin/dashboard.html",
        students=results,
        search_query=query,
        current_month=current_month_str,
    )


@app.route("/admin-student-profile/<int:student_id>")
@admin_required
def admin_student_profile(student_id):
    """Renders the full unmasked student dossier for administrators."""
    conn = get_db_connection()
    _ensure_fees_table(conn)
    student = conn.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
    fees = conn.execute(
        "SELECT * FROM fees WHERE student_id = ? ORDER BY id DESC",
        (student_id,),
    ).fetchall()
    conn.close()

    if not student:
        return redirect(url_for("admin_manage_students"))

    full_student = _sanitize_student_for_frontend(student, include_full_dossier=True)
    return render_template("admin/student_details.html", student=full_student, fees=fees)


# ==============================================================================
# SECTION 8: ADMIN STUDENT LIFECYCLE ROUTES (APPROVALS, EDITS & ADD/EDIT)
# ==============================================================================

# --- 8.1.1 Pending Registration Approval Queue ---
@app.route("/admin/registrations")
@admin_required
def admin_registrations():
    """Lists pending student registrations for admin review."""
    conn = get_db_connection()
    raw_pending = conn.execute("SELECT * FROM students WHERE status = 'Pending' ORDER BY id DESC").fetchall()
    conn.close()

    pending_students = [_sanitize_student_for_frontend(r, include_full_dossier=False) for r in raw_pending]
    return render_template("admin/approval.html", pending_students=pending_students)


@app.route("/approve/<int:student_id>")
@admin_required
def approve_student(student_id):
    """Approves a pending student registration and sets status to Active."""
    conn = get_db_connection()
    conn.execute("UPDATE students SET status = 'Active' WHERE id = ?", (student_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_registrations"))


@app.route("/delete/<int:student_id>")
@admin_required
def delete_student(student_id):
    """Rejects and deletes a pending student registration."""
    conn = get_db_connection()
    conn.execute("DELETE FROM students WHERE id = ? AND status = 'Pending'", (student_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_registrations"))


# --- 8.2.1 Profile Edit Requests Queue & Inline Updates ---
@app.route("/admin/edit-requests", methods=["GET", "POST"])
@admin_required
def admin_edit_requests():
    """Displays pending profile edit requests and supports direct student updates."""
    conn = get_db_connection()
    _ensure_student_lifecycle_columns(conn)
    _ensure_profile_edit_requests_table(conn)
    today_str = datetime.now().strftime("%Y-%m-%d")

    if request.method == "POST":
        action = (request.form.get("action") or "update_student").strip()
        msg = ""
        ok = False
        student_payload = None

        try:
            if action == "update_student":
                student_id = request.form.get("student_id", type=int)
                if not student_id:
                    msg = "Missing Student ID."
                else:
                    ok, msg, student_payload = _apply_direct_student_edit(
                        conn, student_id, request.form, request.files, today_str
                    )
            else:
                msg = "Unsupported action."
        except sqlite3.Error as db_err:
            conn.rollback()
            msg = f"Database error: {db_err}"
        except Exception as exc:
            conn.rollback()
            msg = f"Error updating student details: {exc}"

        conn.close()
        if msg:
            session["edit_req_flash"] = msg
            session["edit_req_status"] = "success" if ok else "error"

        if _is_ajax_request():
            return jsonify({
                "ok": ok,
                "status_type": "success" if ok else "error",
                "message": msg,
                "student": student_payload,
            }), (200 if ok else 400)

        return redirect(url_for("admin_edit_requests"))

    flash_msg = session.pop("edit_req_flash", None)
    flash_status = session.pop("edit_req_status", "success")

    raw_requests = conn.execute("""
        SELECT
            per.*,
            s.username AS username,
            s.email AS current_email,
            s.phone AS current_phone,
            s.mother_name AS current_mother_name,
            s.batch AS current_batch,
            s.village AS current_village,
            s.post AS current_post,
            s.police_station AS current_police_station,
            s.block AS current_block,
            s.subdivision AS current_subdivision,
            s.district AS current_district,
            s.state AS current_state,
            s.country AS current_country,
            s.pincode AS current_pincode,
            s.status AS current_status,
            s.deactivated_at AS current_deactivated_at,
            s.leaving_reason AS current_leaving_reason,
            s.school_class AS school_class,
            s.photo AS current_photo,
            s.name AS current_name,
            s.father_name AS current_father_name,
            s.dob AS current_dob,
            s.gender AS current_gender,
            s.aadhaar AS current_aadhaar,
            s.aadhaar_doc AS current_aadhaar_doc
        FROM profile_edit_requests per
        JOIN students s ON per.student_id = s.id
        WHERE per.status = 'Pending'
        ORDER BY per.id DESC
    """).fetchall()

    batch_rows = conn.execute(
        "SELECT DISTINCT batch FROM students WHERE batch IS NOT NULL AND TRIM(batch) != '' ORDER BY batch ASC"
    ).fetchall()
    batch_options = [r["batch"].strip() for r in batch_rows] or ["Morning Batch", "Evening Batch"]
    conn.close()

    edit_requests = [_sanitize_edit_request_for_frontend(r) for r in raw_requests]
    return render_template(
        "admin/edit_approval.html",
        edit_requests=edit_requests,
        batch_options=batch_options,
        flash_msg=flash_msg,
        flash_status=flash_status,
    )


@app.route("/admin/edit-requests/<int:req_id>/approve", methods=["POST"])
@admin_required
def approve_edit_request(req_id):
    """Applies a student's requested profile changes and marks the request Approved."""
    conn = get_db_connection()
    _ensure_profile_edit_requests_table(conn)
    req = conn.execute(
        "SELECT * FROM profile_edit_requests WHERE id = ? AND status = 'Pending'",
        (req_id,),
    ).fetchone()

    if req:
        conn.execute(
            """
            UPDATE students
            SET name = COALESCE(NULLIF(?, ''), name),
                father_name = COALESCE(NULLIF(?, ''), father_name),
                dob = COALESCE(NULLIF(?, ''), dob),
                gender = COALESCE(NULLIF(?, ''), gender),
                aadhaar = COALESCE(NULLIF(?, ''), aadhaar),
                aadhaar_doc = COALESCE(NULLIF(?, ''), aadhaar_doc)
            WHERE id = ?
            """,
            (req["name"], req["father_name"], req["dob"], req["gender"], req["aadhaar"], req["proof_doc"], req["student_id"]),
        )
        conn.execute("UPDATE profile_edit_requests SET status = 'Approved' WHERE id = ?", (req_id,))
        conn.commit()
        session["edit_req_flash"] = "Edit request approved and applied to student record."
        session["edit_req_status"] = "success"

    conn.close()
    return redirect(url_for("admin_edit_requests"))


@app.route("/admin/edit-requests/<int:req_id>/reject", methods=["POST"])
@admin_required
def reject_edit_request(req_id):
    """Rejects a pending student profile edit request."""
    conn = get_db_connection()
    _ensure_profile_edit_requests_table(conn)
    conn.execute(
        "UPDATE profile_edit_requests SET status = 'Rejected' WHERE id = ? AND status = 'Pending'",
        (req_id,),
    )
    conn.commit()
    conn.close()
    session["edit_req_flash"] = "Edit request rejected."
    session["edit_req_status"] = "success"
    return redirect(url_for("admin_edit_requests"))


# --- 8.3.1 Direct Register New / Edit Existing Student ---
@app.route("/admin/register-or-edit", methods=["GET", "POST"], endpoint="admin_register_or_edit_student")
@admin_required
def admin_register_or_edit_student():
    """Handles direct student creation and typo-ranked lookup/editing for administrators."""
    conn = get_db_connection()
    _ensure_student_lifecycle_columns(conn)
    _ensure_extended_student_columns(conn)

    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    today_str = now.strftime("%Y-%m-%d")

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        msg = ""
        ok = False

        try:
            if action == "create_student":
                ok, msg, _ = _create_student_record(conn, request.form, request.files, now, now_str, today_str)
            elif action == "update_student":
                student_id = request.form.get("student_id", type=int)
                if not student_id:
                    msg = "Please select a student to edit."
                else:
                    ok, msg, _ = _apply_direct_student_edit(conn, student_id, request.form, request.files, today_str)
            else:
                msg = "Unsupported action."
        except sqlite3.Error as db_err:
            conn.rollback()
            msg = f"Database error: {db_err}"
        except Exception as exc:
            conn.rollback()
            msg = f"Error processing request: {exc}"

        conn.close()
        if msg:
            session["reg_edit_flash"] = msg
            session["reg_edit_status"] = "success" if ok else "error"
        return redirect(url_for("admin_register_or_edit_student"))

    flash_msg = session.pop("reg_edit_flash", None)
    flash_status = session.pop("reg_edit_status", "success")

    do_search = (request.args.get("do_search") or "").strip() == "1"
    search_q = (request.args.get("q") or "").strip()
    batch_filter = (request.args.get("batch") or "").strip()
    status_filter = (request.args.get("status") or "All").strip()
    if status_filter not in ("All", "Active", "Inactive"):
        status_filter = "All"

    batch_rows = conn.execute(
        "SELECT DISTINCT batch FROM students WHERE batch IS NOT NULL AND TRIM(batch) != '' ORDER BY batch ASC"
    ).fetchall()
    batch_options = [r["batch"].strip() for r in batch_rows] or ["Morning Batch", "Evening Batch"]

    matched_students = []
    if do_search:
        sql = """
            SELECT
                id,
                COALESCE(name, '') AS name,
                COALESCE(father_name, '') AS father_name,
                COALESCE(mother_name, '') AS mother_name,
                COALESCE(dob, '') AS dob,
                COALESCE(gender, '') AS gender,
                COALESCE(phone, '') AS phone,
                COALESCE(aadhaar, '') AS aadhaar,
                COALESCE(username, '') AS username,
                COALESCE(email, '') AS email,
                COALESCE(school_class, '') AS school_class,
                COALESCE(batch, 'Morning Batch') AS batch,
                COALESCE(country, 'India') AS country,
                COALESCE(state, 'Bihar') AS state,
                COALESCE(district, 'Begusarai') AS district,
                COALESCE(subdivision, 'Teghra') AS subdivision,
                COALESCE(block, '') AS block,
                COALESCE(panchayat, '') AS panchayat,
                COALESCE(village, '') AS village,
                COALESCE(post, '') AS post,
                COALESCE(police_station, '') AS police_station,
                COALESCE(pincode, '') AS pincode,
                COALESCE(photo, '') AS photo,
                COALESCE(aadhaar_doc, '') AS aadhaar_doc,
                COALESCE(status, 'Active') AS status,
                COALESCE(deactivated_at, '') AS deactivated_at,
                COALESCE(leaving_reason, '') AS leaving_reason
            FROM students
            WHERE COALESCE(status, 'Active') != 'Pending'
        """
        params = []
        if batch_filter:
            sql += " AND batch = ?"
            params.append(batch_filter)
        if status_filter in ("Active", "Inactive"):
            sql += " AND COALESCE(status, 'Active') = ?"
            params.append(status_filter)
        sql += " ORDER BY CASE WHEN COALESCE(status, 'Active') = 'Active' THEN 0 ELSE 1 END, name ASC"

        all_rows = conn.execute(sql, params).fetchall()
        ranked_rows = _filter_and_rank_students(all_rows, search_q) if search_q else list(all_rows)
        for r in ranked_rows:
            matched_students.append(_sanitize_student_for_frontend(r, include_full_dossier=False))

    conn.close()
    return render_template(
        "admin/register_or_edit_student.html",
        students=matched_students,
        search_executed=do_search,
        batch_options=batch_options,
        search_q=search_q,
        batch_filter=batch_filter,
        status_filter=status_filter,
        photo_display_max_kb=PHOTO_DISPLAY_MAX_KB,
        photo_actual_max_kb=PHOTO_ACTUAL_MAX_BYTES // 1024,
        aadhaar_max_kb=AADHAAR_MAX_BYTES // 1024,
        flash_msg=flash_msg,
        flash_status=flash_status,
    )


# ==============================================================================
# SECTION 9: ADMIN ATTENDANCE, ROSTER & FEE LEDGER ROUTES
# ==============================================================================

# --- 9.1.1 Active/Inactive Status & Daily Attendance Marking ---
@app.route("/admin/students", methods=["GET", "POST"], endpoint="admin_manage_students")
@admin_required
def admin_manage_students():
    """Manages student Active/Inactive lifecycle toggles and attendance records."""
    conn = get_db_connection()
    _ensure_student_lifecycle_columns(conn)
    _ensure_attendance_table(conn)

    now = datetime.now()
    today_str = now.strftime("%Y-%m-%d")

    if request.method == "POST":
        action = (request.form.get("action") or "mark_attendance").strip()
        msg = ""
        ok = False
        student_payload = None

        try:
            if action == "mark_attendance":
                student_id = request.form.get("student_id", type=int)
                att_date = (request.form.get("att_date") or today_str).strip() or today_str
                att_status = (request.form.get("att_status") or "Present").strip()
                if att_status not in ("Present", "Absent", "Leave"):
                    att_status = "Present"
                remark = (request.form.get("remark") or "").strip()

                st_row = conn.execute("SELECT id, name, batch FROM students WHERE id = ?", (student_id,)).fetchone()
                if not student_id or not st_row:
                    msg = "Student not found."
                else:
                    conn.execute(
                        """
                        INSERT INTO attendance (student_id, att_date, status, batch, remark, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(student_id, att_date) DO UPDATE SET
                            status = excluded.status,
                            batch = excluded.batch,
                            remark = excluded.remark,
                            updated_at = excluded.updated_at
                        """,
                        (student_id, att_date, att_status, st_row["batch"], remark, now.strftime("%Y-%m-%d %H:%M:%S")),
                    )
                    conn.commit()
                    msg = f"Attendance marked {att_status} for {st_row['name']} on {att_date}."
                    ok = True

            elif action == "toggle_status":
                student_id = request.form.get("student_id", type=int)
                target_status = "Inactive" if (request.form.get("target_status") == "Inactive") else "Active"
                leaving_reason = (request.form.get("leaving_reason") or "").strip()

                row = conn.execute("SELECT name FROM students WHERE id = ?", (student_id,)).fetchone()
                if not student_id or not row:
                    msg = "Student not found."
                else:
                    if target_status == "Inactive":
                        conn.execute(
                            "UPDATE students SET status = 'Inactive', deactivated_at = ?, leaving_reason = ? WHERE id = ?",
                            (today_str, leaving_reason or "Left institution", student_id),
                        )
                        msg = f"Marked {row['name']} as Deactivated (Left Institution)."
                    else:
                        conn.execute(
                            "UPDATE students SET status = 'Active', deactivated_at = NULL, leaving_reason = '' WHERE id = ?",
                            (student_id,),
                        )
                        msg = f"Re-activated {row['name']} as an Active student."
                    conn.commit()
                    updated_row = conn.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
                    if updated_row:
                        student_payload = _sanitize_student_for_frontend(updated_row, include_full_dossier=False)
                    ok = True
            else:
                msg = "Unsupported action on attendance & status page."

        except sqlite3.Error as db_err:
            conn.rollback()
            msg = f"Database error: {db_err}"
        except Exception as exc:
            conn.rollback()
            msg = f"Error processing request: {exc}"

        conn.close()
        if msg:
            session["student_mgr_flash"] = msg
            session["student_mgr_status"] = "success" if ok else "error"

        if _is_ajax_request():
            return jsonify({
                "ok": ok,
                "status_type": "success" if ok else "error",
                "message": msg,
                "student": student_payload,
            }), (200 if ok else 400)

        return redirect(
            url_for(
                "admin_manage_students",
                tab=request.form.get("tab") or "All",
                batch=request.form.get("batch") or "",
                att_date=request.form.get("att_date") or today_str,
                q=request.form.get("q") or "",
            )
        )

    flash_msg = session.pop("student_mgr_flash", None)
    flash_status = session.pop("student_mgr_status", "success")

    tab_filter = (request.args.get("tab") or "All").strip()
    if tab_filter not in ("All", "Active", "Inactive"):
        tab_filter = "All"
    batch_filter = (request.args.get("batch") or "").strip()
    att_date = (request.args.get("att_date") or today_str).strip() or today_str
    search_q = (request.args.get("q") or "").strip()

    batch_rows = conn.execute(
        "SELECT DISTINCT batch FROM students WHERE batch IS NOT NULL AND TRIM(batch) != '' ORDER BY batch ASC"
    ).fetchall()
    batch_options = [r["batch"].strip() for r in batch_rows] or ["Morning Batch", "Evening Batch"]

    count_sql = """
        SELECT
            COUNT(*) AS total_count,
            SUM(CASE WHEN COALESCE(status, 'Active') = 'Active' THEN 1 ELSE 0 END) AS active_count,
            SUM(CASE WHEN COALESCE(status, 'Active') = 'Inactive' THEN 1 ELSE 0 END) AS inactive_count
        FROM students
        WHERE COALESCE(status, 'Active') != 'Pending'
    """
    count_params = []
    if batch_filter:
        count_sql += " AND batch = ?"
        count_params.append(batch_filter)
    counts_row = conn.execute(count_sql, count_params).fetchone()

    active_count = int(counts_row["active_count"] or 0)
    inactive_count = int(counts_row["inactive_count"] or 0)
    total_count = int(counts_row["total_count"] or 0)

    att_date_rows = conn.execute(
        """
        SELECT student_id, status AS att_status, COALESCE(remark, '') AS att_remark, COALESCE(updated_at, '') AS att_updated_at
        FROM attendance
        WHERE att_date = ?
        """,
        (att_date,),
    ).fetchall()
    att_by_student = {r["student_id"]: dict(r) for r in att_date_rows}

    att_summary_rows = conn.execute(
        """
        SELECT
            student_id,
            SUM(CASE WHEN status = 'Present' THEN 1 ELSE 0 END) AS present_days,
            SUM(CASE WHEN status = 'Absent' THEN 1 ELSE 0 END) AS absent_days,
            SUM(CASE WHEN status = 'Leave' THEN 1 ELSE 0 END) AS leave_days
        FROM attendance
        GROUP BY student_id
        """
    ).fetchall()
    att_totals_by_student = {r["student_id"]: dict(r) for r in att_summary_rows}

    list_sql = """
        SELECT
            id,
            COALESCE(name, '') AS name,
            COALESCE(father_name, '') AS father_name,
            COALESCE(dob, '') AS dob,
            COALESCE(gender, '') AS gender,
            COALESCE(phone, '') AS phone,
            COALESCE(username, '') AS username,
            COALESCE(school_class, '') AS school_class,
            COALESCE(batch, 'Morning Batch') AS batch,
            COALESCE(village, '') AS village,
            COALESCE(status, 'Active') AS status,
            COALESCE(deactivated_at, '') AS deactivated_at,
            COALESCE(leaving_reason, '') AS leaving_reason
        FROM students
        WHERE COALESCE(status, 'Active') != 'Pending'
    """
    list_params = []
    if batch_filter:
        list_sql += " AND batch = ?"
        list_params.append(batch_filter)
    if tab_filter == "Active":
        list_sql += " AND COALESCE(status, 'Active') = 'Active'"
    elif tab_filter == "Inactive":
        list_sql += " AND COALESCE(status, 'Active') = 'Inactive'"
    list_sql += " ORDER BY CASE WHEN COALESCE(status, 'Active') = 'Active' THEN 0 ELSE 1 END, name ASC"

    raw_students = conn.execute(list_sql, list_params).fetchall()
    conn.close()

    ordered_students = _filter_and_rank_students(raw_students, search_q) if search_q else list(raw_students)

    students_list = []
    present_today_count = 0
    absent_today_count = 0

    for r in ordered_students:
        st_safe = _sanitize_student_for_frontend(r, include_full_dossier=False)
        day_rec = att_by_student.get(r["id"], {})
        tot_rec = att_totals_by_student.get(r["id"], {})

        day_status = day_rec.get("att_status") or "Unmarked"
        if day_status == "Present":
            present_today_count += 1
        elif day_status == "Absent":
            absent_today_count += 1

        st_safe["att_status"] = day_status
        st_safe["att_remark"] = day_rec.get("att_remark") or ""
        st_safe["present_days"] = int(tot_rec.get("present_days") or 0)
        st_safe["absent_days"] = int(tot_rec.get("absent_days") or 0)
        st_safe["leave_days"] = int(tot_rec.get("leave_days") or 0)
        students_list.append(st_safe)

    return render_template(
        "admin/manage_students.html",
        students=students_list,
        active_count=active_count,
        inactive_count=inactive_count,
        total_count=total_count,
        present_today_count=present_today_count,
        absent_today_count=absent_today_count,
        att_date=att_date,
        today_date=today_str,
        tab_filter=tab_filter,
        batch_filter=batch_filter,
        batch_options=batch_options,
        search_q=search_q,
        flash_msg=flash_msg,
        flash_status=flash_status,
    )


# --- 9.2.1 Roster Cards & Daily/Monthly Attendance Lookup ---
@app.route("/admin/roster", methods=["GET", "POST"], endpoint="admin_roster")
@admin_required
def admin_roster():
    """Renders student roster cards and daily/monthly attendance search reports."""
    conn = get_db_connection()
    _ensure_student_lifecycle_columns(conn)
    _ensure_attendance_table(conn)

    now = datetime.now()
    today_str = now.strftime("%Y-%m-%d")
    print_timestamp_str = now.strftime("%d %b %Y, %I:%M %p")
    current_year_str = str(now.year)
    current_month_name = now.strftime("%B")
    month_to_num = {m: f"{idx + 1:02d}" for idx, m in enumerate(MONTH_NAMES)}
    year_options = [str(y) for y in range(now.year - 2, now.year + 4)]

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        student_id = request.form.get("student_id", type=int)

        if action == "toggle_status" and student_id:
            target_status = "Inactive" if (request.form.get("target_status") == "Inactive") else "Active"
            leaving_reason = (request.form.get("leaving_reason") or "").strip()
            st_row = conn.execute("SELECT id, name FROM students WHERE id = ?", (student_id,)).fetchone()

            if st_row:
                if target_status == "Inactive":
                    conn.execute(
                        "UPDATE students SET status = 'Inactive', deactivated_at = ?, leaving_reason = ? WHERE id = ?",
                        (today_str, leaving_reason or "Left institution", student_id),
                    )
                    session["roster_flash_msg"] = f"Marked {st_row['name']} as Deactivated (Left Institution)."
                else:
                    conn.execute(
                        "UPDATE students SET status = 'Active', deactivated_at = NULL, leaving_reason = '' WHERE id = ?",
                        (student_id,),
                    )
                    session["roster_flash_msg"] = f"Marked {st_row['name']} as Active."
                conn.commit()

        conn.close()
        return redirect(url_for("admin_roster"))

    roster_flash_msg = session.pop("roster_flash_msg", None)
    att_searched = (request.args.get("att_searched") or "").strip() == "1"
    show_roster_list = (request.args.get("roster_show") or "").strip() == "1"

    tab_filter = (request.args.get("tab") or "All").strip()
    if tab_filter not in ("All", "Active", "Inactive"):
        tab_filter = "All"
    selected_batch = (request.args.get("batch") or "").strip()
    search_q = (request.args.get("q") or "").strip()

    att_date = (request.args.get("att_date") or today_str).strip() or today_str
    att_class = (request.args.get("att_class") or "").strip()
    att_name = " ".join((request.args.get("att_name") or "").split())
    att_month = (request.args.get("att_month") or current_month_name).strip()
    if att_month not in MONTH_NAMES:
        att_month = current_month_name
    att_year = (request.args.get("att_year") or current_year_str).strip() or current_year_str

    raw_mode = (request.args.get("att_mode") or "").strip().lower()
    att_mode = raw_mode if raw_mode in ("daily", "monthly") else ("monthly" if att_name else "daily")
    is_monthly_mode = att_mode == "monthly"

    all_non_pending = conn.execute(
        """
        SELECT
            id, name, username, batch, status, school_class, phone, email,
            aadhaar, gender, village, father_name, deactivated_at, leaving_reason
        FROM students
        WHERE COALESCE(status, 'Active') != 'Pending'
        ORDER BY CASE WHEN COALESCE(status, 'Active') = 'Active' THEN 0 ELSE 1 END, name ASC
        """
    ).fetchall()

    batch_options = sorted({(r["batch"] or "Morning Batch").strip() for r in all_non_pending if (r["batch"] or "").strip()}) or ["Morning Batch", "Evening Batch"]
    class_options = sorted({(r["school_class"] or "").strip() for r in all_non_pending if (r["school_class"] or "").strip()})

    scoped_for_counts = [
        r for r in all_non_pending
        if not selected_batch or (r["batch"] or "Morning Batch").strip() == selected_batch
    ]
    active_count = sum(1 for r in scoped_for_counts if (r["status"] or "Active") == "Active")
    inactive_count = sum(1 for r in scoped_for_counts if r["status"] == "Inactive")
    total_count = len(scoped_for_counts)

    roster_rows = []
    if show_roster_list:
        filtered_roster = []
        for r in scoped_for_counts:
            st_status = r["status"] or "Active"
            if tab_filter == "Active" and st_status != "Active":
                continue
            if tab_filter == "Inactive" and st_status != "Inactive":
                continue
            filtered_roster.append(r)

        ranked_roster = _filter_and_rank_students(filtered_roster, search_q) if search_q else filtered_roster
        for r in ranked_roster:
            safe_st = _sanitize_student_for_frontend(r, include_full_dossier=False)
            safe_st["batch"] = (r["batch"] or "Morning Batch").strip()
            safe_st["status"] = r["status"] or "Active"
            roster_rows.append(safe_st)

    daily_rows = []
    student_match_list = []
    present_count = 0
    absent_count = 0
    leave_count = 0
    unmarked_count = 0

    if att_searched:
        if is_monthly_mode:
            ym_prefix = f"{att_year}-{month_to_num[att_month]}-"
            matched_month_students = (
                _filter_and_rank_students(all_non_pending, att_name)
                if att_name
                else list(all_non_pending)
            )
            for r in matched_month_students:
                name_val = (r["name"] or "").strip()
                st_class = (r["school_class"] or "").strip() or "N/A"
                month_rec_rows = conn.execute(
                    """
                    SELECT att_date, status, COALESCE(remark, '') AS remark
                    FROM attendance
                    WHERE student_id = ? AND att_date LIKE ?
                    ORDER BY att_date ASC
                    """,
                    (r["id"], f"{ym_prefix}%"),
                ).fetchall()

                m_present = sum(1 for x in month_rec_rows if x["status"] == "Present")
                m_absent = sum(1 for x in month_rec_rows if x["status"] == "Absent")
                m_leave = sum(1 for x in month_rec_rows if x["status"] == "Leave")

                present_count += m_present
                absent_count += m_absent
                leave_count += m_leave

                student_match_list.append({
                    "id": r["id"],
                    "name": name_val,
                    "school_class": st_class,
                    "month_records": [dict(x) for x in month_rec_rows],
                    "m_present": m_present,
                    "m_absent": m_absent,
                    "m_leave": m_leave,
                })
        else:
            att_day_rows = conn.execute("SELECT student_id, status FROM attendance WHERE att_date = ?", (att_date,)).fetchall()
            att_map = {r["student_id"]: (r["status"] or "Unmarked") for r in att_day_rows}

            for r in all_non_pending:
                if (r["status"] or "Active") != "Active":
                    continue
                st_class = (r["school_class"] or "").strip()
                if att_class and st_class.lower() != att_class.lower():
                    continue

                day_state = att_map.get(r["id"], "Unmarked")
                if day_state == "Present":
                    present_count += 1
                elif day_state == "Absent":
                    absent_count += 1
                elif day_state == "Leave":
                    leave_count += 1
                else:
                    unmarked_count += 1

                daily_rows.append({
                    "student_id": r["id"],
                    "name": r["name"],
                    "school_class": st_class or "N/A",
                    "att_date": att_date,
                    "att_status": day_state,
                })

    conn.close()
    return render_template(
        "admin/roster_status.html",
        roster_flash_msg=roster_flash_msg,
        att_searched=att_searched,
        show_roster_list=show_roster_list,
        tab_filter=tab_filter,
        selected_batch=selected_batch,
        search_q=search_q,
        batch_options=batch_options,
        class_options=class_options,
        active_count=active_count,
        inactive_count=inactive_count,
        total_count=total_count,
        roster_rows=roster_rows,
        att_mode=att_mode,
        is_monthly_mode=is_monthly_mode,
        att_date=att_date,
        att_class=att_class,
        att_name=att_name,
        att_month=att_month,
        att_year=att_year,
        month_options=MONTH_NAMES,
        year_options=year_options,
        daily_rows=daily_rows,
        student_match_list=student_match_list,
        present_count=present_count,
        absent_count=absent_count,
        leave_count=leave_count,
        unmarked_count=unmarked_count,
        print_timestamp_str=print_timestamp_str,
    )


# --- 9.3.1 Fee Collection, Deposit Recording & Printable Ledger ---
@app.route("/admin/fees", methods=["GET", "POST"])
@admin_required
def admin_fee_ledger():
    """Handles admin fee statistics, deposit recording/clearing, and printable ledgers."""
    conn = get_db_connection()
    _ensure_fees_table(conn)

    now = datetime.now()
    current_year = str(now.year)
    current_month_name = now.strftime("%B")

    if request.method == "POST":
        action_type = (request.form.get("action_type") or "save").strip()
        student_id = request.form.get("student_id", type=int)
        month_year = _resolve_fee_month_year(request.form, current_month_name, current_year)

        raw_amount = (request.form.get("amount") or "").strip()
        payment_date = (request.form.get("payment_date") or "").strip() or now.strftime("%Y-%m-%d")
        receipt_no = (request.form.get("receipt_no") or "").strip()
        search_q = (request.form.get("search_q") or "").strip()

        raw_stat_month = (request.form.get("stat_month") or "").strip()
        stat_month = raw_stat_month if raw_stat_month in (MONTH_NAMES + ["Whole Year"]) else current_month_name
        stat_year = (request.form.get("stat_year") or request.form.get("bill_year") or current_year).strip()

        raw_ledger_month = (request.form.get("ledger_month") or "").strip()
        if raw_ledger_month == "Whole Year":
            ledger_month = "Whole Year"
        elif raw_ledger_month in MONTH_NAMES:
            ledger_month = raw_ledger_month
        else:
            ledger_month = stat_month if stat_month != "Whole Year" else current_month_name

        ledger_year = (request.form.get("ledger_year") or stat_year or current_year).strip()
        ledger_status = (request.form.get("ledger_status") or "All").strip()
        if ledger_status not in ("All", "Paid", "Unpaid"):
            ledger_status = "All"
        ledger_batch = (request.form.get("ledger_batch") or "").strip()
        ledger_gender = (request.form.get("ledger_gender") or "Both").strip()
        if ledger_gender not in ("Both", "Male", "Female"):
            ledger_gender = "Both"
        ledger_class = (request.form.get("ledger_class") or "").strip()
        ledger_searched = "1" if (request.form.get("ledger_searched") or "0").strip() == "1" else "0"

        redirect_kwargs = {
            "stat_month": stat_month,
            "stat_year": stat_year,
            "month": ledger_month,
            "year": ledger_year,
            "status": ledger_status,
            "batch": ledger_batch,
            "gender": ledger_gender,
            "school_class": ledger_class,
            "ledger_search": ledger_searched,
            "q": search_q,
        }

        msg = ""
        ok = False

        if not student_id or not month_year:
            msg = "Please select a valid student, month, and year."
        else:
            student_row = conn.execute("SELECT name FROM students WHERE id = ?", (student_id,)).fetchone()
            if not student_row:
                msg = "Selected student record was not found."
            else:
                student_name = student_row["name"]
                actor_label, actor_role = _get_session_actor_info("admin")
                now_str = now.strftime("%Y-%m-%d %H:%M:%S")
                resolved_mode = _resolve_payment_mode(request.form)
                try:
                    if action_type == "clear_unpaid":
                        conn.execute("DELETE FROM fees WHERE student_id = ? AND month_year = ?", (student_id, month_year))
                        conn.commit()
                        msg = f"Previous payment cleared and marked as Not Paid for {student_name} ({month_year}) by {actor_label}."
                        ok = True
                    elif not raw_amount:
                        msg = "Please enter a deposit amount before updating."
                    else:
                        amt_val = float(raw_amount)
                        if amt_val <= 0:
                            msg = "Deposit amount must be greater than zero."
                        else:
                            existing = conn.execute(
                                "SELECT id, receipt_no FROM fees WHERE student_id = ? AND month_year = ?",
                                (student_id, month_year),
                            ).fetchone()
                            final_receipt = receipt_no or (
                                existing["receipt_no"] if existing and existing["receipt_no"]
                                else f"KMC-{now.strftime('%Y%m%d%H%M%S')}-{student_id}"
                            )
                            if existing:
                                conn.execute(
                                    """
                                    UPDATE fees
                                    SET amount = ?, payment_date = ?, receipt_no = ?, payment_mode = ?,
                                        status = 'Paid', updated_by = ?, updated_by_role = ?, updated_at = ?
                                    WHERE id = ?
                                    """,
                                    (amt_val, payment_date, final_receipt, resolved_mode, actor_label, actor_role, now_str, existing["id"]),
                                )
                            else:
                                conn.execute(
                                    """
                                    INSERT INTO fees (
                                        student_id, month_year, amount, payment_date, receipt_no,
                                        payment_mode, status, updated_by, updated_by_role, updated_at, created_at
                                    ) VALUES (?, ?, ?, ?, ?, ?, 'Paid', ?, ?, ?, ?)
                                    """,
                                    (
                                        student_id, month_year, amt_val, payment_date,
                                        final_receipt, resolved_mode, actor_label, actor_role, now_str, now_str,
                                    ),
                                )
                            conn.commit()
                            msg = f"Fees have been updated for {student_name} ({month_year}) — ₹{amt_val:g} via {resolved_mode} by {actor_label}."
                            ok = True
                except ValueError:
                    msg = "Please enter a valid numeric amount."
                except sqlite3.Error as db_err:
                    conn.rollback()
                    msg = f"Database error while saving fee: {db_err}"
                    ok = False

        conn.close()
        if msg:
            session["fee_flash_msg"] = msg

        if _is_ajax_request():
            return jsonify({"ok": ok, "message": msg or "Fee updated."}), (200 if ok else 400)

        return redirect(url_for("admin_fee_ledger", **redirect_kwargs))

    flash_msg = session.pop("fee_flash_msg", None)
    ctx = _build_fee_ledger_context(conn, role_key="admin", flash_msg=flash_msg)
    conn.close()
    return render_template("admin/fee_ledger.html", **ctx)


# --- 9.4.1 Admin Instant Fee Student Suggestions JSON Endpoint ---
@app.route("/admin/fees/suggest", methods=["GET"])
@admin_required
def admin_fees_suggest():
    """JSON endpoint returning instant ranked student suggestions for admin fee updates."""
    conn = get_db_connection()
    _ensure_fees_table(conn)
    suggestions = _query_fee_student_suggestions(
        conn=conn,
        query_text=request.args.get("q", ""),
        batch_filter=(request.args.get("batch") or "").strip(),
        gender_filter=(request.args.get("gender") or "Both").strip(),
        class_filter=(request.args.get("school_class") or "").strip(),
        limit=8,
    )
    conn.close()
    return jsonify({"suggestions": suggestions})

# ==============================================================================
# SECTION 10: TEACHER PORTAL ROUTES (AUTH, DASHBOARD, APPROVALS, FEES & EXPORTS)
# ==============================================================================

# --- 10.1.1 Teacher Authentication & Session Cleanup ---
@app.route("/teacher-login", methods=["POST"], endpoint="teacher_login")
def teacher_login():
    """Authenticates teacher credentials against `teachers.password_hash`."""
    conn = get_db_connection()
    _ensure_teachers_and_audit_tables(conn)
    username = (request.form.get("username") or "").strip().lower()
    password = (request.form.get("password") or "").strip()

    teacher = conn.execute(
        "SELECT * FROM teachers WHERE LOWER(username) = ?",
        (username,),
    ).fetchone()
    conn.close()

    if teacher and _verify_password_with_secret(teacher["password_hash"], password, role_name="teachers"):
        session["teacher_id"] = teacher["id"]
        session["teacher_username"] = teacher["username"]
        session["teacher_name"] = teacher["full_name"]
        return redirect(url_for("teacher_dashboard"))

    return render_template("common/index.html", error="Invalid Teacher ID or Password.")


@app.route("/teacher-logout", endpoint="teacher_logout")
def teacher_logout():
    """Clears teacher session keys only."""
    session.pop("teacher_id", None)
    session.pop("teacher_name", None)
    session.pop("teacher_username", None)
    return redirect(url_for("index"))


# --- 10.2.1 Teacher Control Center Dashboard & Ranked Typo Search ---
@app.route("/teacher/dashboard", methods=["GET"], endpoint="teacher_dashboard")
@teacher_required
def teacher_dashboard():
    """Renders teacher summary cards and typo-ranked student lookup results."""
    conn = get_db_connection()
    _ensure_teachers_and_audit_tables(conn)
    _ensure_student_lifecycle_columns(conn)
    _ensure_attendance_table(conn)
    _ensure_fees_table(conn)
    _ensure_profile_edit_requests_table(conn)

    now = datetime.now()
    today_str = now.strftime("%Y-%m-%d")
    current_month_str = now.strftime("%B %Y")
    teacher_id = session["teacher_id"]
    search_query = (request.args.get("q") or "").strip()

    teacher_row = conn.execute("SELECT * FROM teachers WHERE id = ?", (teacher_id,)).fetchone()
    pending_reg_count = conn.execute("SELECT COUNT(*) FROM students WHERE status = 'Pending'").fetchone()[0]
    pending_edit_count = conn.execute("SELECT COUNT(*) FROM profile_edit_requests WHERE status = 'Pending'").fetchone()[0]
    active_count = conn.execute(
        "SELECT COUNT(*) FROM students WHERE COALESCE(status, 'Active') = 'Active'"
    ).fetchone()[0]
    enrolled_count = conn.execute(
        "SELECT COUNT(*) FROM students WHERE COALESCE(status, 'Active') != 'Pending'"
    ).fetchone()[0]

    total_paid = conn.execute(
        """
        SELECT COUNT(*)
        FROM fees f
        JOIN students s ON f.student_id = s.id
        WHERE f.month_year = ? AND f.status = 'Paid' AND COALESCE(s.status, 'Active') = 'Active'
        """,
        (current_month_str,),
    ).fetchone()[0]
    total_unpaid = max(0, active_count - total_paid)

    present_today_count = conn.execute(
        "SELECT COUNT(*) FROM attendance WHERE att_date = ? AND status = 'Present'",
        (today_str,),
    ).fetchone()[0]
    absent_today_count = conn.execute(
        "SELECT COUNT(*) FROM attendance WHERE att_date = ? AND status = 'Absent'",
        (today_str,),
    ).fetchone()[0]

    matched_students = []
    if search_query:
        all_non_pending = conn.execute(
            """
            SELECT * FROM students
            WHERE COALESCE(status, 'Active') != 'Pending'
            ORDER BY name ASC
            """
        ).fetchall()
        ranked = _filter_and_rank_students(all_non_pending, search_query)
        matched_students = [_sanitize_student_for_teacher(r) for r in ranked]

    conn.close()

    return render_template(
        "teacher/teacher_dashboard.html",
        teacher=dict(teacher_row) if teacher_row else {},
        today_str=today_str,
        current_month=current_month_str,
        pending_reg_count=pending_reg_count,
        pending_edit_count=pending_edit_count,
        active_count=active_count,
        enrolled_count=enrolled_count,
        total_paid=total_paid,
        total_unpaid=total_unpaid,
        present_today_count=present_today_count,
        absent_today_count=absent_today_count,
        search_query=search_query,
        students=matched_students,
    )


# --- 10.3.1 Pending Admissions & Edit Approvals Queue ---
@app.route("/teacher/registrations", methods=["GET", "POST"], endpoint="teacher_registrations")
@teacher_required
def teacher_registrations():
    """Renders teacher approvals queue and handles same-page saves and edit approvals."""
    conn = get_db_connection()
    _ensure_teachers_and_audit_tables(conn)
    _ensure_student_lifecycle_columns(conn)
    _ensure_student_approval_columns(conn)
    _ensure_extended_student_columns(conn)
    _ensure_profile_edit_requests_table(conn)

    teacher_id = session.get("teacher_id")
    today_str = datetime.now().strftime("%Y-%m-%d")

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        req_id = request.form.get("req_id", type=int)
        student_id = request.form.get("student_id", type=int)
        return_tab = (request.form.get("return_tab") or "new").strip()
        if return_tab not in ("new", "edit"):
            return_tab = "new"

        try:
            if action == "save_pending_student" and student_id:
                form_payload = dict(request.form)
                form_payload["status"] = "Pending"
                ok, msg, _ = _apply_direct_student_edit(conn, student_id, form_payload, request.files, today_str)
                if ok:
                    _log_teacher_activity(
                        conn,
                        teacher_id,
                        "EDIT_PENDING_STUDENT",
                        f"Saved edits on pending student #{student_id} (kept Pending)",
                    )
                    conn.commit()
                else:
                    conn.rollback()
                session["teacher_flash_msg"] = msg
                session["teacher_flash_status"] = "success" if ok else "error"
                session["teacher_return_tab"] = "new"

            elif action == "approve_edit_req" and req_id:
                req = conn.execute(
                    "SELECT * FROM profile_edit_requests WHERE id = ? AND status = 'Pending'",
                    (req_id,),
                ).fetchone()
                if req:
                    req_dict = dict(req)
                    req_cols = {
                        row["name"]
                        for row in conn.execute("PRAGMA table_info(profile_edit_requests)").fetchall()
                    }
                    optional_fields = [
                        "mother_name", "phone", "email", "school_class",
                        "village", "post", "block", "district", "state", "pincode",
                    ]
                    set_clauses = [
                        "name = COALESCE(NULLIF(?, ''), name)",
                        "father_name = COALESCE(NULLIF(?, ''), father_name)",
                        "dob = COALESCE(NULLIF(?, ''), dob)",
                        "gender = COALESCE(NULLIF(?, ''), gender)",
                        "aadhaar = COALESCE(NULLIF(?, ''), aadhaar)",
                        "aadhaar_doc = COALESCE(NULLIF(?, ''), aadhaar_doc)",
                    ]
                    params = [
                        req_dict.get("name"),
                        req_dict.get("father_name"),
                        req_dict.get("dob"),
                        req_dict.get("gender"),
                        req_dict.get("aadhaar"),
                        req_dict.get("proof_doc"),
                    ]
                    for col in optional_fields:
                        if col in req_cols:
                            set_clauses.append(f"{col} = COALESCE(NULLIF(?, ''), {col})")
                            params.append(req_dict.get(col))

                    params.append(req_dict["student_id"])
                    conn.execute(
                        f"UPDATE students SET {', '.join(set_clauses)} WHERE id = ?",
                        params,
                    )
                    conn.execute(
                        "UPDATE profile_edit_requests SET status = 'Approved' WHERE id = ?",
                        (req_id,),
                    )
                    _log_teacher_activity(
                        conn,
                        teacher_id,
                        "APPROVE_EDIT",
                        f"Approved edit request #{req_id} for student #{req_dict['student_id']}",
                    )
                    conn.commit()
                    session["teacher_flash_msg"] = f"Edit request #{req_id} approved and applied."
                    session["teacher_flash_status"] = "success"
                else:
                    session["teacher_flash_msg"] = "Pending edit request not found."
                    session["teacher_flash_status"] = "error"
                session["teacher_return_tab"] = "edit"

            elif action == "reject_edit_req" and req_id:
                cur = conn.execute(
                    "UPDATE profile_edit_requests SET status = 'Rejected' WHERE id = ? AND status = 'Pending'",
                    (req_id,),
                )
                if cur.rowcount:
                    _log_teacher_activity(
                        conn,
                        teacher_id,
                        "REJECT_EDIT",
                        f"Rejected edit request #{req_id}",
                    )
                    conn.commit()
                    session["teacher_flash_msg"] = f"Edit request #{req_id} rejected."
                    session["teacher_flash_status"] = "success"
                else:
                    session["teacher_flash_msg"] = "Pending edit request not found."
                    session["teacher_flash_status"] = "error"
                session["teacher_return_tab"] = "edit"

            else:
                session["teacher_flash_msg"] = "Invalid or missing request details."
                session["teacher_flash_status"] = "error"
                session["teacher_return_tab"] = return_tab

        except sqlite3.Error as db_err:
            conn.rollback()
            app.logger.exception("SQLite error in teacher_registrations POST")
            session["teacher_flash_msg"] = f"Database error: {db_err}"
            session["teacher_flash_status"] = "error"
            session["teacher_return_tab"] = return_tab

        conn.close()
        return redirect(url_for("teacher_registrations"))

    raw_pending = conn.execute(
        "SELECT * FROM students WHERE status = 'Pending' ORDER BY id DESC"
    ).fetchall()

    raw_edits = conn.execute(
        """
        SELECT per.*,
               s.name AS current_name,
               s.father_name AS current_father_name,
               s.dob AS current_dob,
               s.gender AS current_gender,
               s.aadhaar AS current_aadhaar,
               s.username AS student_username,
               s.school_class AS school_class,
               s.batch AS batch
        FROM profile_edit_requests per
        JOIN students s ON per.student_id = s.id
        WHERE per.status = 'Pending'
        ORDER BY per.id DESC
        """
    ).fetchall()
    conn.close()

    flash_msg = session.pop("teacher_flash_msg", None)
    flash_status = session.pop("teacher_flash_status", "success")
    return_tab = session.pop("teacher_return_tab", None)
    pending_students = [_sanitize_student_for_teacher(r) for r in raw_pending]
    pending_edits = [_sanitize_edit_request_for_frontend(r) for r in raw_edits]

    return render_template(
        "teacher/new_approval_by_teacher.html",
        pending_students=pending_students,
        pending_edits=pending_edits,
        teacher_name=session.get("teacher_name", "Teacher"),
        teacher_username=session.get("teacher_username", ""),
        flash_msg=flash_msg,
        flash_status=flash_status,
        return_tab=return_tab,
    )


@app.route("/teacher/pending-student/<int:student_id>", methods=["GET", "POST"], endpoint="teacher_pending_student_review")
@teacher_required
def teacher_pending_student_review(student_id):
    """Reviews/edits a pending admission and optionally activates it."""
    conn = get_db_connection()
    _ensure_student_lifecycle_columns(conn)
    _ensure_extended_student_columns(conn)
    _ensure_student_approval_columns(conn)
    _ensure_teachers_and_audit_tables(conn)

    today_str = datetime.now().strftime("%Y-%m-%d")
    student_row = conn.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
    if not student_row:
        conn.close()
        return redirect(url_for("teacher_registrations"))

    batch_rows = conn.execute(
        "SELECT DISTINCT batch FROM students WHERE batch IS NOT NULL AND TRIM(batch) != '' ORDER BY batch ASC"
    ).fetchall()
    batch_options = [r["batch"].strip() for r in batch_rows] or ["Morning Batch", "Evening Batch"]

    msg = ""
    ok = False

    if request.method == "POST":
        submit_mode = (request.form.get("submit_mode") or "save_only").strip()
        ok, msg, _ = _apply_direct_student_edit(conn, student_id, request.form, request.files, today_str)

        if ok and submit_mode == "save_and_approve":
            teacher_id = session.get("teacher_id")
            t_user = (session.get("teacher_username") or "teacher").strip()
            t_full = (session.get("teacher_name") or "Teacher").strip()
            approver_label = f"{t_full} (@{t_user})"

            conn.execute(
                """
                UPDATE students
                SET status = 'Active', approved_by_teacher = ?, approved_by_role = 'Teacher'
                WHERE id = ?
                """,
                (approver_label, student_id),
            )
            _log_teacher_activity(
                conn,
                teacher_id,
                "APPROVE_ADMISSION",
                f"Edited & approved pending student #{student_id} as {approver_label}",
            )
            conn.commit()
            conn.close()
            session["teacher_flash_msg"] = f"Updated and approved student #{student_id} ({approver_label})."
            session["teacher_flash_status"] = "success"
            return redirect(url_for("teacher_registrations"))

        student_row = conn.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()

    conn.close()
    safe_student = _sanitize_student_for_teacher(student_row)
    return render_template(
        "teacher/pending_student_review.html",
        student=safe_student,
        batch_options=batch_options,
        msg=msg,
        ok=ok,
    )


@app.route("/teacher/approve/<int:student_id>", methods=["POST"], endpoint="teacher_approve_student")
@teacher_required
def teacher_approve_student(student_id):
    """Approves a pending student admission and records approving faculty."""
    conn = get_db_connection()
    _ensure_teachers_and_audit_tables(conn)
    _ensure_student_approval_columns(conn)

    teacher_id = session.get("teacher_id")
    t_row = conn.execute("SELECT username, full_name FROM teachers WHERE id = ?", (teacher_id,)).fetchone()
    t_user = (t_row["username"] if t_row and t_row["username"] else session.get("teacher_username") or "teacher").strip()
    t_full = (t_row["full_name"] if t_row and t_row["full_name"] else session.get("teacher_name") or "Teacher").strip()

    approver_label = f"{t_full} (@{t_user})"
    st_row = conn.execute("SELECT name FROM students WHERE id = ? AND status = 'Pending'", (student_id,)).fetchone()

    if st_row:
        conn.execute(
            """
            UPDATE students
            SET status = 'Active', approved_by_teacher = ?, approved_by_role = 'Teacher'
            WHERE id = ?
            """,
            (approver_label, student_id),
        )
        _log_teacher_activity(
            conn,
            teacher_id,
            "APPROVE_ADMISSION",
            f"Approved new admission for {st_row['name']} (#{student_id}) as {approver_label}",
        )
        conn.commit()
        session["teacher_flash_msg"] = f"Approved new admission for {st_row['name']} ({approver_label})."
        session["teacher_flash_status"] = "success"
    else:
        session["teacher_flash_msg"] = "Pending student application not found."
        session["teacher_flash_status"] = "error"

    conn.close()
    return redirect(url_for("teacher_registrations"))


@app.route("/teacher/reject/<int:student_id>", methods=["POST"], endpoint="teacher_reject_student")
@teacher_required
def teacher_reject_student(student_id):
    """Rejects and removes a pending student admission application."""
    conn = get_db_connection()
    _ensure_teachers_and_audit_tables(conn)
    teacher_id = session.get("teacher_id")

    st_row = conn.execute("SELECT name FROM students WHERE id = ? AND status = 'Pending'", (student_id,)).fetchone()
    if st_row:
        conn.execute("DELETE FROM students WHERE id = ? AND status = 'Pending'", (student_id,))
        _log_teacher_activity(
            conn,
            teacher_id,
            "REJECT_ADMISSION",
            f"Rejected pending admission for {st_row['name']} (#{student_id})",
        )
        conn.commit()
        session["teacher_flash_msg"] = f"Rejected admission for {st_row['name']}."
        session["teacher_flash_status"] = "success"
    else:
        session["teacher_flash_msg"] = "Pending student application not found."
        session["teacher_flash_status"] = "error"

    conn.close()
    return redirect(url_for("teacher_registrations"))


# --- 10.4.1 Teacher Register New / Edit Existing Student ---
@app.route("/teacher/register-or-edit", methods=["GET", "POST"], endpoint="teacher_register_or_edit")
@teacher_required
def teacher_register_or_edit():
    """Allows teachers to register a new student or edit an existing student with typo-ranked lookup."""
    conn = get_db_connection()
    _ensure_teachers_and_audit_tables(conn)
    _ensure_student_lifecycle_columns(conn)
    _ensure_extended_student_columns(conn)
    _ensure_registered_by_columns(conn)

    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    today_str = now.strftime("%Y-%m-%d")
    teacher_id = session["teacher_id"]
    teacher_name = session.get("teacher_name", "Teacher")
    teacher_username = session.get("teacher_username", "")
    teacher_label = f"{teacher_name} (@{teacher_username})" if teacher_username else teacher_name

    msg = ""
    ok = False
    active_mode = None

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        try:
            if action in ("create_student", "register_new_student"):
                ok, msg, created_payload = _create_student_record(
                    conn, request.form, request.files, now, now_str, today_str
                )
                if ok:
                    new_sid = created_payload.get("id") if isinstance(created_payload, dict) else None
                    if new_sid:
                        conn.execute(
                            """
                            UPDATE students
                            SET registered_by_teacher = COALESCE(NULLIF(registered_by_teacher, ''), ?),
                                registered_by_teacher_id = COALESCE(registered_by_teacher_id, ?)
                            WHERE id = ?
                            """,
                            (teacher_label, teacher_id, new_sid),
                        )
                    else:
                        conn.execute(
                            """
                            UPDATE students
                            SET registered_by_teacher = COALESCE(NULLIF(registered_by_teacher, ''), ?),
                                registered_by_teacher_id = COALESCE(registered_by_teacher_id, ?)
                            WHERE id = (SELECT MAX(id) FROM students)
                            """,
                            (teacher_label, teacher_id),
                        )
                    _log_teacher_activity(
                        conn,
                        teacher_id,
                        "CREATE_STUDENT",
                        f"{msg[:110]} | Registered by {teacher_label}",
                    )
                    conn.commit()
                    active_mode = "edit"
                else:
                    conn.rollback()
                    active_mode = "register"

            elif action in ("update_student", "edit_existing_student"):
                sid = request.form.get("student_id", type=int)
                if not sid:
                    msg = "Please select a student to update."
                else:
                    ok, msg, _ = _apply_direct_student_edit(
                        conn, sid, request.form, request.files, today_str
                    )
                    if ok:
                        conn.execute(
                            """
                            UPDATE students
                            SET registered_by_teacher = COALESCE(NULLIF(registered_by_teacher, ''), ?)
                            WHERE id = ?
                            """,
                            (teacher_label, sid),
                        )
                        _log_teacher_activity(
                            conn, teacher_id, "EDIT_STUDENT", f"Edited student #{sid}"
                        )
                        conn.commit()
                    else:
                        conn.rollback()
                active_mode = "edit"
            else:
                msg = "Unsupported action."
        except sqlite3.Error as db_err:
            conn.rollback()
            msg = f"Database error: {db_err}"

    q = (request.args.get("q") or "").strip()
    edit_id = request.args.get("edit_id", type=int)

    all_students = conn.execute(
        "SELECT * FROM students WHERE COALESCE(status, 'Active') != 'Pending' ORDER BY LOWER(TRIM(name)) ASC, id ASC"
    ).fetchall()
    batch_rows = conn.execute(
        "SELECT DISTINCT batch FROM students WHERE batch IS NOT NULL AND TRIM(batch) != '' ORDER BY batch ASC"
    ).fetchall()
    batch_options = [r["batch"].strip() for r in batch_rows] or ["Morning Batch", "Evening Batch"]

    def _build_student_row(row):
        item = _sanitize_student_for_teacher(row)
        raw_dict = dict(row)
        item["registered_by_teacher"] = (
            raw_dict.get("registered_by_teacher")
            or raw_dict.get("created_by_teacher")
            or raw_dict.get("added_by")
            or "Student / Self Portal"
        )
        return item

    ranked_rows = _filter_and_rank_students(all_students, q) if q else list(all_students)
    matched_students = [_build_student_row(r) for r in ranked_rows]

    selected_student = None
    if edit_id:
        found = conn.execute("SELECT * FROM students WHERE id = ?", (edit_id,)).fetchone()
        if found:
            selected_student = _build_student_row(found)

    conn.close()
    return render_template(
        "teacher/teacher_register_or_edit.html",
        students=matched_students,
        selected_student=selected_student,
        batch_options=batch_options,
        teacher_name=teacher_name,
        teacher_username=teacher_username,
        today_str=today_str,
        search_q=q,
        msg=msg,
        ok=ok,
        active_mode=active_mode,
    )


# --- 10.5.1 Teacher Single-Day Attendance & Class/Monthly Reports ---
@app.route("/teacher/attendance", methods=["GET", "POST"], endpoint="teacher_attendance")
@teacher_required
def teacher_attendance():
    """On-demand daily attendance marking (P/A/L), typo dropdown search, and reports/PDF."""
    conn = get_db_connection()
    _ensure_teachers_and_audit_tables(conn)
    _ensure_student_lifecycle_columns(conn)
    _ensure_extended_student_columns(conn)
    _ensure_attendance_table(conn)

    now = datetime.now()
    today_str = now.strftime("%Y-%m-%d")
    current_month = now.strftime("%Y-%m")
    teacher_id = session["teacher_id"]
    teacher_name = session.get("teacher_name", "Teacher")
    teacher_username = session.get("teacher_username", "")
    teacher_label = f"{teacher_name} (@{teacher_username})" if teacher_username else teacher_name

    msg = ""
    ok = False
    active_mode = (request.args.get("mode") or "").strip() or None
    selected_date = (request.args.get("date") or today_str).strip()
    if selected_date > today_str:
        selected_date = today_str

    selected_class = (request.args.get("class") or "").strip()
    selected_batch = (request.args.get("batch") or "").strip()
    typo_q = (request.args.get("typo_q") or "").strip()
    typo_triggered = (request.args.get("typo_run") or "").strip() == "1"

    report_scope = (request.args.get("report_scope") or "day").strip()
    report_class = (request.args.get("report_class") or "").strip()
    report_batch = (request.args.get("report_batch") or "").strip()
    report_date = (request.args.get("report_date") or today_str).strip()
    if report_date > today_str:
        report_date = today_str
    report_month = (request.args.get("report_month") or current_month).strip()
    report_student_id = request.args.get("report_student_id", type=int)
    report_rows = None
    report_title = ""
    report_subtitle = ""

    class_rows = conn.execute(
        """
        SELECT DISTINCT TRIM(school_class) AS cls
        FROM students
        WHERE school_class IS NOT NULL AND TRIM(school_class) != ''
        ORDER BY LOWER(TRIM(school_class)) ASC
        """
    ).fetchall()
    class_options = [r["cls"] for r in class_rows]

    batch_rows = conn.execute(
        """
        SELECT DISTINCT TRIM(batch) AS bat
        FROM students
        WHERE batch IS NOT NULL AND TRIM(batch) != ''
        ORDER BY LOWER(TRIM(batch)) ASC
        """
    ).fetchall()
    batch_options = [r["bat"] for r in batch_rows]

    code_to_status = {"P": "Present", "A": "Absent", "L": "Leave"}
    status_to_code = {"Present": "P", "Absent": "A", "Leave": "L"}

    def _normalize_student_row(r):
        d = dict(r)
        return {
            "id": d.get("id"),
            "name": (d.get("name") or "").strip(),
            "father_name": (d.get("father_name") or "").strip(),
            "school_class": (d.get("school_class") or "").strip(),
            "batch": (d.get("batch") or "").strip(),
        }

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()

        if action == "save_attendance":
            active_mode = "mark"
            att_date = (request.form.get("attendance_date") or today_str).strip()
            selected_class = (request.form.get("active_class") or "").strip()
            selected_batch = (request.form.get("active_batch") or "").strip()

            if att_date > today_str:
                msg = "Future dates are not allowed for attendance."
                ok = False
                selected_date = today_str
            else:
                selected_date = att_date
                submitted_ids = [
                    k[5:] for k in request.form.keys()
                    if k.startswith("mark_") and k[5:].isdigit()
                ]
                saved_count = 0
                try:
                    for sid_str in submitted_ids:
                        sid = int(sid_str)
                        code = (request.form.get(f"mark_{sid}") or "").strip().upper()
                        st_r = conn.execute("SELECT batch FROM students WHERE id = ?", (sid,)).fetchone()
                        st_batch = (st_r["batch"] if st_r and st_r["batch"] else selected_batch or "").strip()
                        if code in code_to_status:
                            conn.execute(
                                """
                                INSERT INTO attendance (student_id, att_date, status, batch, marked_by_teacher, updated_at)
                                VALUES (?, ?, ?, ?, ?, ?)
                                ON CONFLICT(student_id, att_date)
                                DO UPDATE SET status = excluded.status,
                                              batch = excluded.batch,
                                              marked_by_teacher = excluded.marked_by_teacher,
                                              updated_at = excluded.updated_at
                                """,
                                (sid, att_date, code_to_status[code], st_batch, teacher_label, now.strftime("%Y-%m-%d %H:%M:%S")),
                            )
                            saved_count += 1
                        else:
                            conn.execute(
                                "DELETE FROM attendance WHERE student_id = ? AND att_date = ?",
                                (sid, att_date),
                            )
                    _log_teacher_activity(
                        conn, teacher_id, "MARK_ATTENDANCE",
                        f"Saved {saved_count} attendance marks for {att_date}",
                    )
                    conn.commit()
                    msg = f"Attendance saved for {att_date} ({saved_count} marked)."
                    ok = True
                except sqlite3.Error as db_err:
                    conn.rollback()
                    msg = f"Database error: {db_err}"
                    ok = False

        elif action == "generate_report":
            active_mode = "report"
            report_scope = (request.form.get("report_scope") or "day").strip()
            report_class = (request.form.get("report_class") or "").strip()
            report_batch = (request.form.get("report_batch") or "").strip()
            report_date = (request.form.get("report_date") or today_str).strip()
            if report_date > today_str:
                report_date = today_str
            report_month = (request.form.get("report_month") or current_month).strip()
            report_student_id = request.form.get("report_student_id", type=int)
            typo_q = (request.form.get("typo_q_keep") or "").strip()
            if typo_q:
                typo_triggered = True
            download_pdf = (request.form.get("download_pdf") or "0").strip() == "1"

            if report_scope == "student_month" and not report_student_id:
                msg = "Please search and select a student from the dropdown first."
                ok = False
            elif report_scope != "student_month" and not report_class:
                msg = "Please select a Class or All Classes before generating the report."
                ok = False
            else:
                sql = "SELECT id, name, father_name, school_class, batch FROM students WHERE 1=1"
                params = []
                if report_scope == "student_month" and report_student_id:
                    sql += " AND id = ?"
                    params.append(report_student_id)
                else:
                    if report_class and report_class.lower() != "all":
                        sql += " AND LOWER(TRIM(COALESCE(school_class, ''))) = LOWER(?)"
                        params.append(report_class)
                    if report_batch and report_batch.lower() != "all":
                        sql += " AND LOWER(TRIM(COALESCE(batch, ''))) = LOWER(?)"
                        params.append(report_batch)

                raw_rep_students = conn.execute(sql, params).fetchall()
                rep_students = [_normalize_student_row(r) for r in raw_rep_students]

                if report_scope == "day" and report_class.lower() != "all":
                    rep_students.sort(key=lambda s: (s["name"].lower(), s["id"] or 0))
                else:
                    rep_students.sort(key=lambda s: ((s["school_class"] or "ZZZ").lower(), s["name"].lower(), s["id"] or 0))

                cls_label = "All Classes" if report_class.lower() == "all" else (report_class or "All Classes")
                bat_label = "All Batches" if (not report_batch or report_batch.lower() == "all") else report_batch
                report_rows = []

                if report_scope == "day":
                    report_title = f"Single-Day Attendance Report — {cls_label} ({bat_label})"
                    report_subtitle = f"Date: {report_date} | Sorted by: {'Class -> Name (A-Z)' if cls_label == 'All Classes' else 'Name (A-Z)'}"
                    att_rows = conn.execute(
                        "SELECT student_id, status FROM attendance WHERE att_date = ?",
                        (report_date,),
                    ).fetchall()
                    day_lookup = {r["student_id"]: (r["status"] or "Unmarked") for r in att_rows}
                    for s in rep_students:
                        report_rows.append({
                            "name": s["name"],
                            "father_name": s["father_name"],
                            "school_class": s["school_class"] or "Unassigned",
                            "batch": s["batch"] or "Unassigned",
                            "attendance_date": report_date,
                            "status_label": day_lookup.get(s["id"], "Unmarked"),
                        })
                else:
                    if report_scope == "student_month":
                        stu_nm = rep_students[0]["name"] if rep_students else "Selected Student"
                        report_title = f"Single Student Monthly Attendance — {stu_nm}"
                        report_subtitle = f"Month: {report_month}"
                    else:
                        report_title = f"Monthly Attendance Report — {cls_label} ({bat_label})"
                        report_subtitle = f"Month: {report_month}"

                    att_rows = conn.execute(
                        """
                        SELECT student_id, att_date, status
                        FROM attendance
                        WHERE att_date LIKE ?
                        ORDER BY att_date ASC
                        """,
                        (f"{report_month}-%",),
                    ).fetchall()
                    by_student = {}
                    for r in att_rows:
                        code = status_to_code.get(r["status"], (r["status"] or "")[:1].upper())
                        by_student.setdefault(r["student_id"], []).append((r["att_date"], code))

                    for s in rep_students:
                        entries = by_student.get(s["id"], [])
                        p_cnt = sum(1 for _, c in entries if c == "P")
                        a_cnt = sum(1 for _, c in entries if c == "A")
                        l_cnt = sum(1 for _, c in entries if c == "L")
                        breakdown = ", ".join(f"{d[-2:]}:{c}" for d, c in entries if c)
                        report_rows.append({
                            "name": s["name"],
                            "father_name": s["father_name"],
                            "school_class": s["school_class"] or "Unassigned",
                            "batch": s["batch"] or "Unassigned",
                            "p_count": p_cnt,
                            "a_count": a_cnt,
                            "l_count": l_cnt,
                            "day_breakdown": breakdown,
                        })

                if download_pdf:
                    if report_scope == "day":
                        if cls_label == "All Classes":
                            grouped = {}
                            for r in report_rows:
                                grouped.setdefault(r["school_class"], []).append(r)
                            pages = []
                            for c_name in sorted(grouped.keys(), key=lambda x: x.lower()):
                                c_lines = [
                                    f"{i:02d}. {r['name']} | S/o {r['father_name'] or '-'} | Batch: {r['batch']}  -->  [{r['status_label']}]"
                                    for i, r in enumerate(grouped[c_name], 1)
                                ]
                                pages.append((
                                    f"KM Campus — Single-Day Attendance ({c_name})",
                                    f"Date: {report_date} | Batch: {bat_label} | Students: {len(c_lines)}",
                                    c_lines,
                                ))
                            pdf_bytes = _generate_pdf_bytes(
                                report_title,
                                report_subtitle,
                                pages or [(report_title, report_subtitle, ["No students found."])],
                            )
                        else:
                            single_lines = [
                                f"{i:02d}. {r['name']} | S/o {r['father_name'] or '-'} | Batch: {r['batch']}  -->  [{r['status_label']}]"
                                for i, r in enumerate(report_rows, 1)
                            ]
                            pdf_bytes = _generate_pdf_bytes(
                                f"KM Campus — Single-Day Attendance ({cls_label})",
                                f"Date: {report_date} | Batch: {bat_label} | Students: {len(single_lines)}",
                                single_lines or ["No students found."],
                            )
                    elif report_scope == "student_month":
                        s_lines = []
                        for i, r in enumerate(report_rows, 1):
                            s_lines.append(f"{i}. {r['name']} | S/o {r['father_name'] or '-'} | Batch: {r['batch']}")
                            s_lines.append(f"   Month ({report_month}) Summary: Present = {r['p_count']} | Absent = {r['a_count']} | Leave = {r['l_count']}")
                            s_lines.append(f"   Daily Log: {r['day_breakdown'] or 'No attendance recorded for this month.'}")
                        pdf_bytes = _generate_pdf_bytes(
                            report_title,
                            f"{report_subtitle} | Generated: {now.strftime('%d %b %Y %I:%M %p')}",
                            s_lines or ["No records found."],
                        )
                    else:
                        grouped = {}
                        for r in report_rows:
                            grouped.setdefault(r["school_class"], []).append(r)
                        pages = []
                        for c_name in sorted(grouped.keys(), key=lambda x: x.lower()):
                            c_lines = [
                                f"{i:02d}. {r['name']} | S/o {r['father_name'] or '-'} | Batch: {r['batch']}  -->  P:{r['p_count']}  A:{r['a_count']}  L:{r['l_count']}"
                                for i, r in enumerate(grouped[c_name], 1)
                            ]
                            pages.append((
                                f"KM Campus — Monthly Attendance ({c_name})",
                                f"Month: {report_month} | Batch: {bat_label} | Students: {len(c_lines)}",
                                c_lines,
                            ))
                        pdf_bytes = _generate_pdf_bytes(
                            report_title,
                            report_subtitle,
                            pages or [(report_title, report_subtitle, ["No students found."])],
                        )

                    conn.close()
                    return Response(
                        pdf_bytes,
                        mimetype="application/pdf",
                        headers={
                            "Content-Disposition": f"attachment; filename=attendance_{report_scope}_{report_month if report_scope != 'day' else report_date}.pdf"
                        },
                    )

    roster_students = []
    typo_dropdown_items = []

    if typo_triggered and typo_q:
        all_rows = conn.execute("SELECT * FROM students ORDER BY LOWER(TRIM(COALESCE(name, ''))) ASC, id ASC").fetchall()
        ranked_typo_rows = _filter_and_rank_students(all_rows, typo_q)
        for r in ranked_typo_rows:
            norm = _normalize_student_row(r)
            if active_mode == "report":
                if report_class and report_class.lower() != "all" and norm["school_class"].lower() != report_class.lower():
                    continue
                if report_batch and report_batch.lower() != "all" and norm["batch"].lower() != report_batch.lower():
                    continue
            else:
                if selected_class and selected_class.lower() != "all" and norm["school_class"].lower() != selected_class.lower():
                    continue
                if selected_batch and selected_batch.lower() != "all" and norm["batch"].lower() != selected_batch.lower():
                    continue
            typo_dropdown_items.append(norm)
        if active_mode == "mark":
            roster_students = typo_dropdown_items
    elif active_mode == "mark" and selected_class:
        sql = "SELECT id, name, father_name, school_class, batch FROM students WHERE 1=1"
        params = []
        if selected_class.lower() != "all":
            sql += " AND LOWER(TRIM(COALESCE(school_class, ''))) = LOWER(?)"
            params.append(selected_class)
        if selected_batch and selected_batch.lower() != "all":
            sql += " AND LOWER(TRIM(COALESCE(batch, ''))) = LOWER(?)"
            params.append(selected_batch)
        sql += " ORDER BY LOWER(TRIM(COALESCE(name, ''))) ASC, id ASC"
        roster_students = [_normalize_student_row(r) for r in conn.execute(sql, params).fetchall()]

    saved_marks = {}
    if roster_students:
        saved_rows = conn.execute(
            "SELECT student_id, status FROM attendance WHERE att_date = ?",
            (selected_date,),
        ).fetchall()
        saved_marks = {
            r["student_id"]: status_to_code[r["status"]]
            for r in saved_rows
            if r["status"] in status_to_code
        }

    conn.close()

    return render_template(
        "teacher/teacher_attendance.html",
        students=roster_students,
        typo_dropdown_items=typo_dropdown_items,
        typo_triggered=typo_triggered,
        class_options=class_options,
        batch_options=batch_options,
        saved_marks=saved_marks,
        today_str=today_str,
        current_month=current_month,
        selected_date=selected_date,
        selected_class=selected_class,
        selected_batch=selected_batch,
        typo_q=typo_q,
        teacher_name=teacher_name,
        active_mode=active_mode,
        report_scope=report_scope,
        report_class=report_class,
        report_batch=report_batch,
        report_date=report_date,
        report_month=report_month,
        report_student_id=report_student_id,
        report_rows=report_rows,
        report_title=report_title,
        report_subtitle=report_subtitle,
        msg=msg,
        ok=ok,
    )


# --- 10.6.1 Teacher Fee Status, Deposit Updates, Ledgers & Suggestions ---
@app.route("/teacher/fees", methods=["GET", "POST"], endpoint="teacher_fees")
@teacher_required
def teacher_fees():
    """
    Unified Teacher Fee & Reports route: supports deposit recording/clearing,
    AJAX/JSON responses, typo-ranked search, overview stats, monthly/yearly
    ledgers, and all variables expected by teacher/teacher_fees.html without 500 errors.
    """
    conn = get_db_connection()
    _ensure_teachers_and_audit_tables(conn)
    _ensure_fees_table(conn)

    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    today_str = now.strftime("%Y-%m-%d")
    current_month_name = now.strftime("%B")
    current_year_str = str(now.year)
    teacher_id = session["teacher_id"]
    actor_label, actor_role = _get_session_actor_info("teacher")

    allowed_fee_periods = _get_allowed_fee_periods(now)
    allowed_fee_labels = {p["label"] for p in allowed_fee_periods}

    msg = ""
    ok = False
    fee_payload = None

    if request.method == "POST":
        req_payload = request.get_json(silent=True) or request.form
        action_type = (req_payload.get("action_type") or "save").strip().lower()
        clear_flag = (
            action_type == "clear_unpaid"
            or str(req_payload.get("clear_fee") or "").strip().lower() in ("1", "true", "yes")
        )
        sid = None
        try:
            raw_sid = req_payload.get("student_id")
            sid = int(raw_sid) if raw_sid is not None and str(raw_sid).strip() != "" else None
        except (TypeError, ValueError):
            sid = None

        fee_period = _resolve_fee_month_year(req_payload, current_month_name, current_year_str)
        raw_amt = str(req_payload.get("amount") or "").strip()
        pay_mode = _resolve_payment_mode(req_payload)
        pay_date = (req_payload.get("payment_date") or today_str).strip() or today_str
        custom_receipt = (req_payload.get("receipt_no") or "").strip()

        st = conn.execute("SELECT id, name FROM students WHERE id = ?", (sid,)).fetchone() if sid else None
        if not st:
            msg = "Selected student record was not found."
        elif not fee_period:
            msg = "Please select a valid month and year."
        elif clear_flag:
            try:
                conn.execute("DELETE FROM fees WHERE student_id = ? AND month_year = ?", (sid, fee_period))
                _log_teacher_activity(
                    conn, teacher_id, "FEE_CLEAR",
                    f"Cleared fee for {st['name']} ({fee_period}) by {actor_label}",
                )
                conn.commit()
                msg = f"Previous payment cleared and marked as Not Paid for {st['name']} ({fee_period}) by {actor_label}."
                ok = True
                fee_payload = {
                    "student_id": sid,
                    "fee_period": fee_period,
                    "status": "Unpaid",
                    "updated_by": actor_label,
                    "updated_at": now_str,
                }
            except sqlite3.Error as db_err:
                conn.rollback()
                msg = f"Database error while clearing fee: {db_err}"
        else:
            if not raw_amt:
                msg = "Please enter a deposit amount before updating."
            else:
                try:
                    amt_val = float(raw_amt)
                    if amt_val <= 0:
                        msg = "Please enter a positive fee amount."
                    elif fee_period not in allowed_fee_labels:
                        msg = "Fee entry/correction is allowed only for the last 2 months, current month, or next 4 months."
                    else:
                        existing = conn.execute(
                            "SELECT id, receipt_no FROM fees WHERE student_id = ? AND month_year = ?",
                            (sid, fee_period),
                        ).fetchone()
                        receipt = (
                            custom_receipt
                            or (existing["receipt_no"] if existing and existing["receipt_no"] else "")
                            or f"TCH-{now.strftime('%Y%m%d%H%M')}-{sid}"
                        )
                        if existing:
                            conn.execute(
                                """
                                UPDATE fees
                                SET amount = ?, payment_date = ?, receipt_no = ?, payment_mode = ?,
                                    status = 'Paid', updated_by = ?, updated_by_role = ?, updated_at = ?
                                WHERE id = ?
                                """,
                                (amt_val, pay_date, receipt, pay_mode, actor_label, actor_role, now_str, existing["id"]),
                            )
                        else:
                            conn.execute(
                                """
                                INSERT INTO fees (
                                    student_id, month_year, amount, payment_date, receipt_no,
                                    payment_mode, status, updated_by, updated_by_role, updated_at, created_at
                                ) VALUES (?, ?, ?, ?, ?, ?, 'Paid', ?, ?, ?, ?)
                                """,
                                (
                                    sid, fee_period, amt_val, pay_date, receipt,
                                    pay_mode, actor_label, actor_role, now_str, now_str,
                                ),
                            )
                        _log_teacher_activity(
                            conn, teacher_id, "FEE_SAVE",
                            f"Saved ₹{amt_val:g} ({receipt}) for {st['name']} ({fee_period}) by {actor_label}",
                        )
                        conn.commit()
                        msg = f"Fees have been updated for {st['name']} ({fee_period}) — ₹{amt_val:g} via {pay_mode} by {actor_label}."
                        ok = True
                        fee_payload = {
                            "student_id": sid,
                            "fee_period": fee_period,
                            "amount": amt_val,
                            "payment_date": pay_date,
                            "receipt_no": receipt,
                            "payment_mode": pay_mode,
                            "status": "Paid",
                            "updated_by": actor_label,
                            "updated_at": now_str,
                        }
                except ValueError:
                    msg = "Please enter a valid numeric fee amount."
                except sqlite3.Error as db_err:
                    conn.rollback()
                    msg = f"Database error while saving fee: {db_err}"

        if _is_ajax_request() or request.is_json:
            conn.close()
            resp = {"ok": ok, "message": msg}
            if fee_payload:
                resp["fee"] = fee_payload
            return jsonify(resp), (200 if ok else 400)

        if msg:
            session["teacher_fee_flash_msg"] = msg

        redirect_kwargs = {
            "stat_month": (request.form.get("stat_month") or current_month_name).strip(),
            "stat_year": (request.form.get("stat_year") or request.form.get("bill_year") or current_year_str).strip(),
            "month": (request.form.get("ledger_month") or "").strip(),
            "year": (request.form.get("ledger_year") or current_year_str).strip(),
            "status": (request.form.get("ledger_status") or "All").strip(),
            "batch": (request.form.get("ledger_batch") or "").strip(),
            "gender": (request.form.get("ledger_gender") or "Both").strip(),
            "school_class": (request.form.get("ledger_class") or "").strip(),
            "ledger_search": (request.form.get("ledger_searched") or "0").strip(),
            "q": (request.form.get("search_q") or "").strip(),
        }
        conn.close()
        return redirect(url_for("teacher_fees", **redirect_kwargs))

    flash_msg = session.pop("teacher_fee_flash_msg", None) or msg
    print_all = (request.args.get("print_all") or "").strip() == "1"

    ctx = _build_fee_ledger_context(
        conn,
        role_key="teacher",
        flash_msg=flash_msg,
        allowed_fee_periods=allowed_fee_periods,
        print_all=print_all,
    )
    ctx["msg"] = msg
    ctx["ok"] = ok

    inspect_id = request.args.get("inspect_id", type=int)
    inspected_student = None
    inspected_fees = []
    if inspect_id:
        found = conn.execute("SELECT * FROM students WHERE id = ?", (inspect_id,)).fetchone()
        if found:
            inspected_student = _sanitize_student_for_teacher(found)
            inspected_fees = [
                _sanitize_fee_row_for_frontend(f, include_receipt=True)
                for f in conn.execute(
                    "SELECT * FROM fees WHERE student_id = ? ORDER BY id DESC",
                    (inspect_id,),
                ).fetchall()
            ]
    ctx["inspected_student"] = inspected_student
    ctx["inspected_fees"] = inspected_fees

    conn.close()
    return render_template("teacher/teacher_fees.html", **ctx)


@app.route("/teacher/fees/suggest", methods=["GET"], endpoint="teacher_fees_suggest")
@teacher_required
def teacher_fees_suggest():
    """JSON endpoint returning instant ranked student suggestions for teacher fee updates."""
    conn = get_db_connection()
    _ensure_fees_table(conn)
    suggestions = _query_fee_student_suggestions(
        conn=conn,
        query_text=request.args.get("q", ""),
        batch_filter=(request.args.get("batch") or "").strip(),
        gender_filter=(request.args.get("gender") or "Both").strip(),
        class_filter=(request.args.get("school_class") or "").strip(),
        limit=8,
    )
    conn.close()
    return jsonify({"suggestions": suggestions})


# --- 10.7.1 Teacher Profile & Activity Log ---
@app.route("/teacher/profile", methods=["GET", "POST"], endpoint="teacher_profile")
@teacher_required
def teacher_profile():
    """Displays and updates the logged-in teacher's profile and credentials."""
    conn = get_db_connection()
    _ensure_teachers_and_audit_tables(conn)

    teacher_id = session["teacher_id"]
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    curr_t = conn.execute("SELECT * FROM teachers WHERE id = ?", (teacher_id,)).fetchone()

    msg = ""
    ok = False

    if request.method == "POST" and curr_t:
        new_username = (request.form.get("new_username") or "").strip().lower()
        new_password = (request.form.get("new_password") or "").strip()
        full_name = (request.form.get("full_name") or "").strip()
        subject = (request.form.get("subject") or "").strip()
        t_phone = (request.form.get("phone") or "").strip()
        t_email = (request.form.get("email") or "").strip()

        if not new_username:
            msg = "User ID cannot be empty."
        elif conn.execute(
            "SELECT id FROM teachers WHERE LOWER(username) = ? AND id != ?",
            (new_username, teacher_id),
        ).fetchone():
            msg = f"User ID '{new_username}' is already taken."
        else:
            conn.execute(
                """
                UPDATE teachers
                SET username = ?, full_name = ?, subject = ?, phone = ?, email = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    new_username,
                    full_name or curr_t["full_name"],
                    subject or curr_t["subject"],
                    t_phone,
                    t_email,
                    now_str,
                    teacher_id,
                ),
            )
            if new_password:
                _save_password_everywhere(conn, "teachers", teacher_id, new_username, new_password)
            _log_teacher_activity(conn, teacher_id, "PROFILE_UPDATE", f"Updated teacher profile ({new_username})")
            conn.commit()
            session["teacher_username"] = new_username
            session["teacher_name"] = full_name or curr_t["full_name"]
            curr_t = conn.execute("SELECT * FROM teachers WHERE id = ?", (teacher_id,)).fetchone()
            msg = "Teacher profile and credentials updated."
            ok = True

    recent_logs = conn.execute(
        "SELECT action_type, detail, created_at FROM teacher_activity_log WHERE teacher_id = ? ORDER BY id DESC LIMIT 15",
        (teacher_id,),
    ).fetchall()
    conn.close()

    return render_template(
        "teacher/teacher_profile.html",
        teacher=dict(curr_t) if curr_t else {},
        recent_logs=[dict(x) for x in recent_logs],
        msg=msg,
        ok=ok,
    )


# --- 10.7.2 Teacher Student Workspace Detail Page ---
@app.route("/teacher/student/<int:student_id>", methods=["GET", "POST"], endpoint="teacher_student_workspace")
@teacher_required
def teacher_student_workspace(student_id):
    """Dedicated page for viewing, editing, or printing a student record."""
    conn = get_db_connection()
    _ensure_teachers_and_audit_tables(conn)
    _ensure_student_lifecycle_columns(conn)
    _ensure_extended_student_columns(conn)
    _ensure_attendance_table(conn)
    _ensure_fees_table(conn)

    today_str = datetime.now().strftime("%Y-%m-%d")
    teacher_id = session["teacher_id"]

    student_row = conn.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
    if not student_row:
        conn.close()
        return redirect(url_for("teacher_dashboard"))

    batch_rows = conn.execute(
        "SELECT DISTINCT batch FROM students WHERE batch IS NOT NULL AND TRIM(batch) != '' ORDER BY batch ASC"
    ).fetchall()
    batch_options = [r["batch"].strip() for r in batch_rows] or ["Morning Batch", "Evening Batch"]

    msg = ""
    ok = False

    if request.method == "POST":
        ok, msg, _ = _apply_direct_student_edit(conn, student_id, request.form, request.files, today_str)
        if ok:
            _log_teacher_activity(conn, teacher_id, "EDIT_STUDENT", f"Updated student #{student_id} from student workspace")
            conn.commit()
        student_row = conn.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()

    fee_rows = [
        dict(f) for f in conn.execute(
            "SELECT * FROM fees WHERE student_id = ? ORDER BY id DESC LIMIT 12",
            (student_id,),
        ).fetchall()
    ]
    att_summary = conn.execute(
        """
        SELECT
            SUM(CASE WHEN status = 'Present' THEN 1 ELSE 0 END) AS present_days,
            SUM(CASE WHEN status = 'Absent' THEN 1 ELSE 0 END) AS absent_days,
            SUM(CASE WHEN status = 'Leave' THEN 1 ELSE 0 END) AS leave_days
        FROM attendance
        WHERE student_id = ?
        """,
        (student_id,),
    ).fetchone()
    conn.close()

    safe_student = _sanitize_student_for_teacher(student_row)
    return render_template(
        "teacher/teacher_student_detail.html",
        student=safe_student,
        batch_options=batch_options,
        fees=fee_rows,
        att_summary=dict(att_summary) if att_summary else {"present_days": 0, "absent_days": 0, "leave_days": 0},
        msg=msg,
        ok=ok,
    )


# --- 10.7.3 Teacher Attendance & Student Profile PDF Exports ---
@app.route("/teacher/export/attendance.pdf", methods=["GET"], endpoint="teacher_export_attendance_pdf")
@teacher_required
def teacher_export_attendance_pdf():
    """Exports a PDF attendance sheet for a chosen date and optional class."""
    att_date = (request.args.get("att_date") or datetime.now().strftime("%Y-%m-%d")).strip()
    cls_filter = (request.args.get("school_class") or "").strip()

    conn = get_db_connection()
    _ensure_attendance_table(conn)
    students = conn.execute(
        "SELECT id, name, school_class, batch FROM students WHERE COALESCE(status, 'Active') != 'Pending' ORDER BY name ASC"
    ).fetchall()
    att_map = {
        r["student_id"]: r["status"]
        for r in conn.execute("SELECT student_id, status FROM attendance WHERE att_date = ?", (att_date,)).fetchall()
    }
    conn.close()

    lines = []
    for idx, s in enumerate(students, start=1):
        s_cls = (s["school_class"] or "N/A").strip()
        if cls_filter and s_cls.lower() != cls_filter.lower():
            continue
        st_val = att_map.get(s["id"], "Unmarked")
        lines.append(f"{idx}. {s['name']} | Class: {s_cls} | Batch: {s['batch'] or 'Morning'} | Status: {st_val}")

    if not lines:
        lines.append("No attendance records found for the selected filter.")

    pdf_bytes = _generate_pdf_bytes(
        "KM Campus - Class Attendance Report",
        f"Date: {att_date} | Class Filter: {cls_filter or 'All Classes'}",
        lines,
    )
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=attendance_{att_date}.pdf"},
    )


@app.route("/teacher/export/student/<int:student_id>.pdf", methods=["GET"], endpoint="teacher_export_student_pdf")
@teacher_required
def teacher_export_student_pdf(student_id):
    """Exports a sanitized PDF student profile with attendance and fee summary."""
    conn = get_db_connection()
    _ensure_attendance_table(conn)
    _ensure_fees_table(conn)

    row = conn.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
    if not row:
        conn.close()
        return redirect(url_for("teacher_dashboard"))

    att_summary = conn.execute(
        """
        SELECT
            SUM(CASE WHEN status = 'Present' THEN 1 ELSE 0 END) AS present_days,
            SUM(CASE WHEN status = 'Absent' THEN 1 ELSE 0 END) AS absent_days,
            SUM(CASE WHEN status = 'Leave' THEN 1 ELSE 0 END) AS leave_days
        FROM attendance
        WHERE student_id = ?
        """,
        (student_id,),
    ).fetchone()
    fee_rows = conn.execute(
        "SELECT month_year, amount, status, payment_date, receipt_no FROM fees WHERE student_id = ? ORDER BY id DESC LIMIT 12",
        (student_id,),
    ).fetchall()
    conn.close()

    safe_st = _sanitize_student_for_teacher(row)
    present_days = int((att_summary["present_days"] if att_summary else 0) or 0)
    absent_days = int((att_summary["absent_days"] if att_summary else 0) or 0)
    leave_days = int((att_summary["leave_days"] if att_summary else 0) or 0)

    lines = [
        f"Student ID: {safe_st.get('id')} | Username: @{safe_st.get('username')}",
        f"Full Name: {safe_st.get('name')} | Status: {safe_st.get('status')}",
        f"Father's Name: {safe_st.get('father_name') or 'N/A'} | Mother's Name: {safe_st.get('mother_name') or 'N/A'}",
        f"DOB: {safe_st.get('dob') or 'N/A'} | Gender: {safe_st.get('gender') or 'N/A'}",
        f"Class: {safe_st.get('school_class') or 'N/A'} | Batch: {safe_st.get('batch') or 'Morning Batch'}",
        f"Contact (Masked): {safe_st.get('phone')} | Email: {safe_st.get('email') or 'N/A'}",
        f"ID Card No (Masked): {safe_st.get('aadhaar') or 'N/A'}",
        f"Address: {safe_st.get('village') or ''}, Post: {safe_st.get('post') or ''}, Block: {safe_st.get('block') or ''}",
        f"Subdivision: {safe_st.get('subdivision') or ''}, District: {safe_st.get('district') or ''}, State: {safe_st.get('state') or ''} - {safe_st.get('pincode') or ''}",
        f"Approved By: {safe_st.get('approved_by_teacher') or 'Admin / System'}",
        "-----------------------------------------------------------------------",
        f"Attendance Summary: Present = {present_days} | Absent = {absent_days} | Leave = {leave_days}",
        "-----------------------------------------------------------------------",
        "Recent Fee History (Up to 12 Months):",
    ]
    if fee_rows:
        for fr in fee_rows:
            lines.append(
                f"  - {fr['month_year']}: {fr['status']} | Rs. {fr['amount']} | Date: {fr['payment_date'] or 'N/A'} | Receipt: {fr['receipt_no'] or 'N/A'}"
            )
    else:
        lines.append("  - No fee records available.")

    pdf_bytes = _generate_pdf_bytes(
        f"KM Campus - Detailed Student Profile: {safe_st.get('name')}",
        "Teacher Export (Masked Contact & ID Number; Document Restricted)",
        lines,
    )
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=student_{student_id}_detailed_profile.pdf"},
    )


# ==============================================================================
# SECTION 11: ERROR HANDLING & APPLICATION ENTRY POINT
# ==============================================================================

# --- 11.1.1 Global 500 Error Handler & WSGI/CLI Entry Point ---
@app.errorhandler(500)
def handle_internal_server_error(exc):
    """Logs unhandled 500 exceptions and returns a readable fallback response."""
    app.logger.exception("Unhandled 500 error in KM Campus app: %s", exc)
    return (
        "<h2>Internal Server Error (500)</h2>"
        "<p>Something went wrong while processing your request. Please check the server error log.</p>",
        500,
    )


# For PythonAnywhere WSGI deployment, set SECRET_KEY in your Web tab / WSGI file
# and reload the web app rather than relying on the local dev fallback.
if __name__ == "__main__":
    app.run(debug=True)
