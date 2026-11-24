import os
import sqlite3
from datetime import datetime
from flask_app import _hash_password_with_secret, DB_PATH, PLAIN_PASS_DB_PATH

NEW_PW = "Adarsh@123"  # Change this to the password you want for student 'adarsh'
TARGET_USERNAME = "adarsh"


def update_student_password():
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row

    student = conn.execute(
        "SELECT id, username, status FROM students WHERE LOWER(username) = ?",
        (TARGET_USERNAME.lower(),),
    ).fetchone()

    if not student:
        conn.close()
        print(f"Student '{TARGET_USERNAME}' not found in {DB_PATH}")
        return

    sid = student["id"]
    uname = student["username"]
    status = student["status"]
    new_hash = _hash_password_with_secret(NEW_PW, role_name="students")

    conn.execute(
        "UPDATE students SET password_hash = ? WHERE id = ?",
        (new_hash, sid),
    )
    conn.commit()
    conn.close()

    if os.path.exists(PLAIN_PASS_DB_PATH):
        pconn = sqlite3.connect(PLAIN_PASS_DB_PATH, timeout=15.0)
        pconn.execute(
            """
            CREATE TABLE IF NOT EXISTS students (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                plain_password TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        pconn.execute(
            """
            INSERT INTO students (user_id, username, plain_password, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username,
                plain_password = excluded.plain_password,
                updated_at = excluded.updated_at
            """,
            (sid, uname, NEW_PW, now_str),
        )
        pconn.commit()
        pconn.close()

    print(f"Updated password for id={sid}, username={uname} (status={status})")


if __name__ == "__main__":
    update_student_password()