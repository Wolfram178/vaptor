import sqlite3
from datetime import datetime

DB_NAME = "vaptor.db"


# ----------------------------
# Connection
# ----------------------------
def get_connection():
    return sqlite3.connect(DB_NAME, check_same_thread=False)

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
    conn = get_connection()
    cursor = conn.cursor()

    start_time = datetime.now().isoformat()

    cursor.execute("""
        INSERT INTO scans (start_time, status)
        VALUES (?, ?)
    """, (start_time, "running"))

    scan_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return scan_id


def complete_scan(scan_id):
    conn = get_connection()
    cursor = conn.cursor()

    end_time = datetime.now().isoformat()

    cursor.execute("""
        UPDATE scans
        SET end_time = ?, status = ?
        WHERE id = ?
    """, (end_time, "completed", scan_id))

    conn.commit()
    conn.close()


# ----------------------------
# Target Management
# ----------------------------
def add_target(scan_id, target):
    conn = get_connection()
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
    conn.close()

    return target_id


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
    conn = get_connection()
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
    conn.close()


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
    conn = get_connection()
    cursor = conn.cursor()

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
        ",".join(finding.get("cve", [])),
        finding.get("cvss_score", ""),
        finding.get("description", ""),
        finding.get("recommendation", ""),
        finding.get("scan_id"),
        finding.get("timestamp", datetime.now().isoformat())
    ))

    conn.commit()
    conn.close()


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