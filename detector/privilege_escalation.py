"""
privilege_escalation.py

Detects repeated failed sudo/su attempts from the same user -
mirrors detect_ssh_bruteforce() exactly: count failed attempts
within a time window, alert once the threshold is crossed, and
group repeat detections into one updated alert instead of
spamming duplicates.
"""

from datetime import datetime, timedelta

from database.database import get_connection


FAILED_ATTEMPT_THRESHOLD = 3
TIME_WINDOW_MINUTES = 5


def detect_privilege_escalation(username, server_label="central"):

    connection = get_connection()
    cursor = connection.cursor()

    now = datetime.now()
    current_time = now.isoformat(timespec="seconds")

    cutoff_time = (
        now - timedelta(minutes=TIME_WINDOW_MINUTES)
    ).isoformat(timespec="seconds")


    # ---------------------------------------------------------
    # Count failed sudo/su attempts from this user within the
    # time window.
    # ---------------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*)
        FROM events
        WHERE event_type IN ('sudo_failed_attempt', 'su_failed_attempt')
        AND username = ?
        AND server_label = ?
        AND timestamp >= ?
    """, (
        username,
        server_label,
        cutoff_time
    ))

    failed_attempts = cursor.fetchone()[0]


    if failed_attempts < FAILED_ATTEMPT_THRESHOLD:

        connection.close()
        return None


    # ---------------------------------------------------------
    # Check for an existing open alert for this user.
    # ---------------------------------------------------------

    cursor.execute("""
        SELECT id, attempt_count, first_seen
        FROM alerts
        WHERE alert_type = 'privilege_escalation_attempt'
        AND source_ip = ?
        AND status = 'open'
        AND server_label = ?
        ORDER BY id DESC
        LIMIT 1
    """, (
        username,
        server_label
    ))

    existing_alert = cursor.fetchone()


    if existing_alert:

        alert_id = existing_alert[0]
        previous_count = existing_alert[1] or 0
        first_seen = existing_alert[2] or current_time

        new_count = max(previous_count, failed_attempts)

        description = (
            f"{new_count} failed privilege escalation attempts "
            f"(sudo/su) by user '{username}'. "
            f"First seen: {first_seen}. Last seen: {current_time}."
        )

        cursor.execute("""
            UPDATE alerts
            SET attempt_count = ?,
                last_seen = ?,
                description = ?
            WHERE id = ?
        """, (
            new_count,
            current_time,
            description,
            alert_id
        ))

        connection.commit()
        connection.close()

        return None


    # ---------------------------------------------------------
    # No existing alert: create a new one.
    # ---------------------------------------------------------

    description = (
        f"{failed_attempts} failed privilege escalation attempts "
        f"(sudo/su) by user '{username}' within "
        f"{TIME_WINDOW_MINUTES} minutes."
    )

    cursor.execute("""
        INSERT INTO alerts
        (
            timestamp, alert_type, source_ip, severity,
            description, status, attempt_count,
            first_seen, last_seen, server_label
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        current_time,
        "privilege_escalation_attempt",
        username,
        "high",
        description,
        "open",
        failed_attempts,
        current_time,
        current_time,
        server_label
    ))

    connection.commit()
    connection.close()

    return {
        "alert_type": "privilege_escalation_attempt",
        "username": username,
        "severity": "high",
        "description": description
    }