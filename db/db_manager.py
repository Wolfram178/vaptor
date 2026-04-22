import sqlite3
import time
from datetime import datetime

DB_NAME = "vaptor.db"
ALLOWED_STAGES = {"nmap", "ssl", "nessus"}


# ----------------------------
# Connection
# ----------------------------
def get_connection():
    conn = sqlite3.connect(DB_NAME, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _execute_with_retry(fn, attempts=5, delay=0.2):
    last_error = None

    for attempt in range(attempts):
        try:
            return fn()
        except sqlite3.OperationalError as exc:
            last_error = exc
            if "locked" not in str(exc).lower() or attempt == attempts - 1:
                raise
            time.sleep(delay * (attempt + 1))

    raise last_error

# ----------------------------
# Initialize Database
# ----------------------------
def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # Table: scans
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        start_time TEXT,
        end_time TEXT,
        status TEXT
    )
    """)

    # Table: targets
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        target TEXT
    )
    """)

    # Table: scan_state
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_state (
        target_id INTEGER,
        nmap_status TEXT,
        ssl_status TEXT,
        nessus_status TEXT,
        last_updated TEXT
    )
    """)

    # Table: findings
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        port TEXT,
        service TEXT,
        tool TEXT,
        severity TEXT,
        issue TEXT,
        cve TEXT,
        cvss_score TEXT,
        description TEXT,
        recommendation TEXT,
        scan_id INTEGER,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()


# ----------------------------
# Scan Management
# ----------------------------
def create_scan():
    def _create():
        conn = get_connection()
        try:
            cursor = conn.cursor()
            start_time = datetime.now().isoformat()
            cursor.execute("""
                INSERT INTO scans (start_time, status)
                VALUES (?, ?)
            """, (start_time, "running"))
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()

    return _execute_with_retry(_create)


def complete_scan(scan_id):
    def _complete():
        conn = get_connection()
        try:
            cursor = conn.cursor()
            end_time = datetime.now().isoformat()
            cursor.execute("""
                UPDATE scans
                SET end_time = ?, status = ?
                WHERE id = ?
            """, (end_time, "completed", scan_id))
            conn.commit()
        finally:
            conn.close()

    _execute_with_retry(_complete)


# ----------------------------
# Target Management
# ----------------------------
def add_target(scan_id, target):
    def _add():
        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO targets (scan_id, target)
                VALUES (?, ?)
            """, (scan_id, target))
            target_id = cursor.lastrowid

            # Initialize scan state
            cursor.execute("""
                INSERT INTO scan_state (
                    target_id,
                    nmap_status,
                    ssl_status,
                    nessus_status,
                    last_updated
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                target_id,
                "pending",
                "pending",
                "pending",
                datetime.now().isoformat()
            ))

            conn.commit()
            return target_id
        finally:
            conn.close()

    return _execute_with_retry(_add)


def get_targets(scan_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, target FROM targets
        WHERE scan_id = ?
    """, (scan_id,))

    results = cursor.fetchall()
    conn.close()

    return results  # [(target_id, target), ...]


# ----------------------------
# State Management
# ----------------------------
def update_state(target_id, stage, status):
    if stage not in ALLOWED_STAGES:
        raise ValueError(f"Unsupported stage: {stage}")

    def _update():
        conn = get_connection()
        try:
            cursor = conn.cursor()
            column = f"{stage}_status"
            query = f"""
                UPDATE scan_state
                SET {column} = ?, last_updated = ?
                WHERE target_id = ?
            """
            cursor.execute(query, (
                status,
                datetime.now().isoformat(),
                target_id
            ))
            conn.commit()
        finally:
            conn.close()

    _execute_with_retry(_update)


def get_scan_state(target_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT nmap_status, ssl_status, nessus_status
        FROM scan_state
        WHERE target_id = ?
    """, (target_id,))

    result = cursor.fetchone()
    conn.close()

    return result


# ----------------------------
# Findings Management
# ----------------------------
def save_finding(finding):
    def _save():
        conn = get_connection()
        try:
            cursor = conn.cursor()
            cve_value = finding.get("cve", [])
            if isinstance(cve_value, str):
                cve_text = cve_value
            elif isinstance(cve_value, (list, tuple, set)):
                cve_text = ",".join(str(item) for item in cve_value if item)
            else:
                cve_text = str(cve_value)

            cursor.execute("""
                INSERT INTO findings (
                    target,
                    port,
                    service,
                    tool,
                    severity,
                    issue,
                    cve,
                    cvss_score,
                    description,
                    recommendation,
                    scan_id,
                    timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding["target"],
                finding.get("port", ""),
                finding.get("service", ""),
                finding.get("tool", ""),
                finding.get("severity", ""),
                finding.get("issue", ""),
                cve_text,
                finding.get("cvss_score", ""),
                finding.get("description", ""),
                finding.get("recommendation", ""),
                finding.get("scan_id"),
                finding.get("timestamp", datetime.now().isoformat())
            ))
            conn.commit()
        finally:
            conn.close()

    _execute_with_retry(_save)


def get_findings(scan_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM findings
        WHERE scan_id = ?
    """, (scan_id,))

    results = cursor.fetchall()
    conn.close()

    return results


# ----------------------------
# Summary (for CLI / reporting)
# ----------------------------
def get_summary(scan_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT severity, COUNT(*)
        FROM findings
        WHERE scan_id = ?
        GROUP BY severity
    """, (scan_id,))

    results = cursor.fetchall()
    conn.close()

    return results
