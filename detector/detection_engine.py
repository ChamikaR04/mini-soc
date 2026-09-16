from datetime import datetime, timedelta
from database.database import get_connection
import time

FAILED_LOGIN_THRESHOLD = 15
TIME_WINDOW_MINUTES = 2
CHECK_INTERVAL_SECONDS = 5


def determine_severity(failed_attempts):
    """
    Scales severity with attempt count, since an internet-facing
    server sees constant background scanning - a burst just over
    the threshold is very different from a sustained large attack.
    """

    if failed_attempts >= 50:
        return "high"
    elif failed_attempts >= 25:
        return "medium"
    else:
        return "low"


def detect_ssh_bruteforce(source_ip):

    connection = get_connection()
    cursor = connection.cursor()

    now = datetime.now()
    current_time = now.isoformat(timespec="seconds")

    cutoff_time = (
        now - timedelta(minutes=TIME_WINDOW_MINUTES)
    ).isoformat(timespec="seconds")

    # ---------------------------------------------------------
    # Count failed SSH logins from this IP within the time
    # window.
    # ---------------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*)
        FROM events
        WHERE event_type = 'ssh_failed_login'
        AND source_ip = ?
        AND timestamp >= ?
    """, (
        source_ip,
        cutoff_time
    ))

    failed_attempts = cursor.fetchone()[0]

    # ---------------------------------------------------------
    # Only generate an alert after the threshold is reached.
    # ---------------------------------------------------------

    if failed_attempts < FAILED_LOGIN_THRESHOLD:

        connection.close()
        return None

    # ---------------------------------------------------------
    # Check whether an OPEN brute-force alert already exists
    # for this source IP.
    # ---------------------------------------------------------

    cursor.execute("""
        SELECT
            id,
            attempt_count,
            first_seen
        FROM alerts
        WHERE alert_type = 'ssh_bruteforce'
        AND source_ip = ?
        AND status = 'open'
        ORDER BY id DESC
        LIMIT 1
    """, (
        source_ip,
    ))

    existing_alert = cursor.fetchone()

    # ---------------------------------------------------------
    # Existing alert found:
    # UPDATE the existing alert instead of creating another one.
    # ---------------------------------------------------------

    if existing_alert:

        alert_id = existing_alert[0]
        previous_count = existing_alert[1] or 0
        first_seen = existing_alert[2] or current_time

        new_count = max(
            previous_count,
            failed_attempts
        )

        new_severity = determine_severity(new_count)

        description = (
            f"{new_count} failed SSH login attempts "
            f"detected from {source_ip}. "
            f"First seen: {first_seen}. "
            f"Last seen: {current_time}."
        )

        cursor.execute("""
            UPDATE alerts
            SET
                attempt_count = ?,
                last_seen = ?,
                description = ?,
                severity = ?
            WHERE id = ?
        """, (
            new_count,
            current_time,
            description,
            new_severity,
            alert_id
        ))

        connection.commit()
        connection.close()

        # No new alert was created.
        return None

    # ---------------------------------------------------------
    # No existing alert:
    # CREATE a new grouped brute-force alert.
    # ---------------------------------------------------------

    severity = determine_severity(failed_attempts)

    description = (
        f"{failed_attempts} failed SSH login attempts "
        f"detected from {source_ip} within "
        f"{TIME_WINDOW_MINUTES} minutes."
    )

    cursor.execute("""
        INSERT INTO alerts
        (
            timestamp,
            alert_type,
            source_ip,
            severity,
            description,
            status,
            attempt_count,
            first_seen,
            last_seen
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        current_time,
        "ssh_bruteforce",
        source_ip,
        severity,
        description,
        "open",
        failed_attempts,
        current_time,
        current_time
    ))

    connection.commit()
    connection.close()

    return {
        "alert_type": "ssh_bruteforce",
        "source_ip": source_ip,
        "severity": severity,
        "description": description
    }


def run_detection_engine():
    print("Mini-SOC Detection Engine started.")
    print(
        f"Checking SSH brute-force detection every "
        f"{CHECK_INTERVAL_SECONDS} seconds..."
    )

    while True:

        connection = None

        try:
            connection = get_connection()
            cursor = connection.cursor()

            cutoff_time = (
                datetime.now()
                - timedelta(minutes=TIME_WINDOW_MINUTES)
            ).isoformat(timespec="seconds")

            cursor.execute("""
                SELECT DISTINCT source_ip
                FROM events
                WHERE event_type = 'ssh_failed_login'
                AND timestamp >= ?
                AND source_ip IS NOT NULL
            """, (
                cutoff_time,
            ))

            source_ips = [
                row[0]
                for row in cursor.fetchall()
            ]

            connection.close()
            connection = None

            if not source_ips:
                print("No recent failed SSH login events.")

            else:
                for source_ip in source_ips:

                    alert = detect_ssh_bruteforce(source_ip)

                    if alert:
                        print("\nSECURITY ALERT")
                        print(f"  Type: {alert['alert_type']}")
                        print(f"  Source IP: {alert['source_ip']}")
                        print(f"  Severity: {alert['severity']}")
                        print(
                            f"  Description: "
                            f"{alert['description']}"
                        )

                    else:
                        print(
                            f"Checked {source_ip} - "
                            f"no new alert."
                        )

        except Exception as e:

            if connection:
                connection.close()

            print(f"Detection engine error: {e}")

        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    run_detection_engine()