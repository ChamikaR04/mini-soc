import sqlite3
from pathlib import Path

DATABASE_PATH = Path(__file__).parent / "soc.db"


def get_connection():
    """Get a connection to the SQLite database."""
    return sqlite3.connect(DATABASE_PATH)


def initialize_database():

    connection = get_connection()
    cursor = connection.cursor()

    # Events table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source_ip TEXT,
            username TEXT,
            severity TEXT,
            message TEXT
        )
    """)

    # Alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            source_ip TEXT,
            severity TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'open',
            attempt_count INTEGER DEFAULT 1,
            first_seen TEXT,
            last_seen TEXT
        )
    """)

    # ---------------------------------------------------------
    # Database migration
    # Add new columns to an existing alerts table if required.
    # ---------------------------------------------------------

    cursor.execute("PRAGMA table_info(alerts)")
    existing_columns = {
        row[1] for row in cursor.fetchall()
    }

    if "attempt_count" not in existing_columns:
        cursor.execute("""
            ALTER TABLE alerts
            ADD COLUMN attempt_count INTEGER DEFAULT 1
        """)

    if "first_seen" not in existing_columns:
        cursor.execute("""
            ALTER TABLE alerts
            ADD COLUMN first_seen TEXT
        """)

    if "last_seen" not in existing_columns:
        cursor.execute("""
            ALTER TABLE alerts
            ADD COLUMN last_seen TEXT
        """)

    connection.commit()
    connection.close()


def insert_event(
    timestamp,
    event_type,
    source_ip=None,
    username=None,
    severity=None,
    message=None,
    server_label="central"
):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO events
        (timestamp, event_type, source_ip, username, severity, message, server_label)
        VALUES (?, ?, ?, ?, ?, ?,?)
    """, (
        timestamp,
        event_type,
        source_ip,
        username,
        severity,
        message,
        server_label
    ))
    MAX_EVENTS = 10000

    cursor.execute("""
    	DELETE FROM events
    	WHERE id NOT IN (
        	SELECT id
        	FROM events
        	ORDER BY id DESC
        	LIMIT ?
	)
    """, (MAX_EVENTS,))




    MAX_ALERTS = 5000

    cursor.execute("""
    	DELETE FROM alerts
    	WHERE id NOT IN (
        	SELECT id
        	FROM alerts
        	ORDER BY id DESC
        	LIMIT ?
    	)
    """, (MAX_ALERTS,))

    connection.commit()
    connection.close()


def insert_alert(
    timestamp,
    alert_type,
    source_ip=None,
    severity="medium",
    description=None,
    server_label="central"
):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO alerts
        (timestamp, alert_type, source_ip, severity, description,
         status, attempt_count, first_seen, last_seen, server_label)
        VALUES (?, ?, ?, ?, ?, 'open', 1, ?, ?, ?)
    """, (
        timestamp,
        alert_type,
        source_ip,
        severity,
        description,
        timestamp,
        timestamp,
        server_label
    ))
    connection.commit()
    connection.close()


if __name__ == "__main__":

    initialize_database()

    print("Database initialized successfully.")
