import sqlite3
import os

# ✅ SAME PATH FOR ALL COMPONENTS
DB_DIR = r"C:\Users\sabee\OneDrive\Desktop\project new\code"
DB_PATH = os.path.join(DB_DIR, "siem_logs.db")

# Ensure folder exists
os.makedirs(DB_DIR, exist_ok=True)

# Connect
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
cursor = conn.cursor()

# ---------------- TABLES ----------------
cursor.execute("""
CREATE TABLE IF NOT EXISTS logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT,
    log_type TEXT,
    message TEXT,
    severity TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS endpoints(
    source TEXT PRIMARY KEY,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_ip TEXT,
    os TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT
)
""")

conn.commit()

# ---------------- FUNCTIONS ----------------
def insert_log(source, log_type, message, severity):
    cursor.execute(
        "INSERT INTO logs (source, log_type, message, severity) VALUES (?, ?, ?, ?)",
        (source, log_type, message, severity)
    )
    conn.commit()


def upsert_endpoint(source, ip, os_name):
    cursor.execute("""
        INSERT INTO endpoints (source, last_seen, last_ip, os)
        VALUES (?, CURRENT_TIMESTAMP, ?, ?)
        ON CONFLICT(source) DO UPDATE SET
            last_seen = CURRENT_TIMESTAMP,
            last_ip = excluded.last_ip,
            os = excluded.os
    """, (source, ip, os_name))
    conn.commit()


def get_recent_logs(source, seconds=60):
    cursor.execute("""
        SELECT log_type, message, severity, timestamp
        FROM logs
        WHERE source = ?
          AND timestamp >= datetime('now', ?)
        ORDER BY timestamp DESC
    """, (source, f'-{seconds} seconds'))
    return cursor.fetchall()


def get_report_data(hours=24):
    cursor.execute("""
        SELECT severity, COUNT(*)
        FROM logs
        WHERE timestamp >= datetime('now', ?)
        GROUP BY severity
    """, (f'-{hours} hours',))
    severity_counts = cursor.fetchall()

    cursor.execute("""
        SELECT source, COUNT(*)
        FROM logs
        WHERE timestamp >= datetime('now', ?)
        GROUP BY source
        ORDER BY COUNT(*) DESC
        LIMIT 10
    """, (f'-{hours} hours',))
    top_sources = cursor.fetchall()

    cursor.execute("""
        SELECT timestamp, source, log_type, severity, message
        FROM logs
        WHERE timestamp >= datetime('now', ?)
          AND severity != 'INFO'
        ORDER BY timestamp DESC
        LIMIT 50
    """, (f'-{hours} hours',))
    recent_alerts = cursor.fetchall()

    return severity_counts, top_sources, recent_alerts
