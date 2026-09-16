import re
import subprocess
import requests
from datetime import datetime

from config import CENTRAL_SERVER_URL, INGEST_API_KEY, SERVER_LABEL, REQUEST_TIMEOUT

SSH_INGEST_URL = CENTRAL_SERVER_URL.rsplit("/", 1)[0] + "/ssh-ingest"


def parse_ssh_log(log_line):

    match = re.search(
        r"Failed password for (?:invalid user )?(\S+) from (\S+)",
        log_line
    )
    if match:
        return {
            "event_type": "ssh_failed_login",
            "source_ip": match.group(2),
            "username": match.group(1),
            "severity": "medium",
            "message": log_line.strip()
        }

    match = re.search(
        r"Accepted (?:password|publickey) for (\S+) from (\S+)",
        log_line
    )
    if match:
        return {
            "event_type": "ssh_successful_login",
            "source_ip": match.group(2),
            "username": match.group(1),
            "severity": "low",
            "message": log_line.strip()
        }

    match = re.search(
        r"Invalid user (\S+) from (\S+)",
        log_line
    )
    if match:
        return {
            "event_type": "ssh_invalid_user",
            "source_ip": match.group(2),
            "username": match.group(1),
            "severity": "medium",
            "message": log_line.strip()
        }

    return None


def send_event(event):
    payload = dict(event)
    payload["server_label"] = SERVER_LABEL
    payload["timestamp"] = datetime.now().isoformat(timespec="seconds")

    try:
        response = requests.post(
            SSH_INGEST_URL,
            json=payload,
            headers={"X-API-Key": INGEST_API_KEY},
            timeout=REQUEST_TIMEOUT
        )
        if response.status_code == 200:
            print(f"[{event['event_type']}] sent: {event['source_ip']}")
        else:
            print(f"Central rejected event: {response.status_code} {response.text}")
    except requests.exceptions.RequestException as error:
        print(f"Failed to send SSH event to central: {error}")


def monitor_ssh_logs():
    print("Mini-SOC remote SSH sender started.")
    print(f"Sending events to: {SSH_INGEST_URL}")
    print("Press Ctrl+C to stop.\n")

    process = subprocess.Popen(
        ["journalctl", "-u", "ssh", "-o", "cat", "-f", "-n", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    try:
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
            event = parse_ssh_log(line)
            if event:
                send_event(event)
    except KeyboardInterrupt:
        print("\nStopping SSH sender...")
    finally:
        process.terminate()


if __name__ == "__main__":
    monitor_ssh_logs()
