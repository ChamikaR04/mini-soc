import re
from datetime import datetime

from database.database import insert_event
from detector.detection_engine import detect_ssh_bruteforce

def parse_ssh_log(log_line):
    """
    Parse an SSH authentication log line.

    Returns a dictionary containing the security event,
    or None if the line is not an SSH authentication event.
    """

    # Failed password
    match = re.search(
        r"Failed password for (?:invalid user )?(\S+) from (\S+)",
        log_line
    )

    if match:
        username = match.group(1)
        source_ip = match.group(2)

        return {
            "event_type": "ssh_failed_login",
            "source_ip": source_ip,
            "username": username,
            "severity": "medium",
            "message": log_line.strip()
        }

    # Successful login
    match = re.search(
        r"Accepted (?:password|publickey) for (\S+) from (\S+)",
        log_line
    )

    if match:
        username = match.group(1)
        source_ip = match.group(2)

        return {
            "event_type": "ssh_successful_login",
            "source_ip": source_ip,
            "username": username,
            "severity": "low",
            "message": log_line.strip()
        }

    # Invalid user
    match = re.search(
        r"Invalid user (\S+) from (\S+)",
        log_line
    )

    if match:
        username = match.group(1)
        source_ip = match.group(2)

        return {
            "event_type": "ssh_invalid_user",
            "source_ip": source_ip,
            "username": username,
            "severity": "medium",
            "message": log_line.strip()
        }

    return None


def process_log_line(log_line):
    event = parse_ssh_log(log_line)

    if event is None:
        print("No SSH security event detected.")
        return

    timestamp = datetime.now().isoformat(timespec="seconds")

    insert_event(
        timestamp=timestamp,
        event_type=event["event_type"],
        source_ip=event["source_ip"],
        username=event["username"],
        severity=event["severity"],
        message=event["message"]
    )

    print("Security event detected:")
    print(f"  Type: {event['event_type']}")
    print(f"  IP: {event['source_ip']}")
    print(f"  User: {event['username']}")
    print(f"  Severity: {event['severity']}")

    if event["event_type"] == "ssh_failed_login":
        alert = detect_ssh_bruteforce(event["source_ip"])

        if alert:
            print("\n SECURITY ALERT")
            print(f"  Type: {alert['alert_type']}")
            print(f"  Source IP: {alert['source_ip']}")
            print(f"  Severity: {alert['severity']}")
            print(f"  Description: {alert['description']}")
 


def monitor_ssh_logs():
    import subprocess

    print("Mini-Soc SSH log collector started.")
    print("monitoring systemd ssh journal....")
    print("Press Ctrl+C to stop.\n")


    process = subprocess.Popen(
        [
            "journalctl",
            "-u","ssh",
            "-o","cat",
            "-f",
            "-n","0"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    try:
        for line in process.stdout:
            line = line.strip()

            if line:
                process_log_line(line)

    except KeyboardInterrupt:
        print("\nStopping SSH log collector ...")

    finally:
        process.terminate()


if __name__ == "__main__":

    monitor_ssh_logs()
