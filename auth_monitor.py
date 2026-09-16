"""
auth_monitor.py

Watches journald (not flat log files - this system has no rsyslog,
so /var/log/auth.log and /var/log/cron.log don't exist) for
security-relevant events beyond SSH logins:

  - sudo usage (successful and failed)
  - su usage (successful and failed)
  - user/group account changes (useradd, usermod, groupadd, userdel,
    groupdel)
  - cron job modifications (crontab -e, new/replaced cron entries)

Uses `journalctl _COMM=<process> -o cat -f -n 0` the same way
log_collector.py already uses `journalctl -u ssh -o cat -f -n 0` for
SSH.

IMPORTANT: `-o cat` strips the syslog process-name prefix (e.g.
"sudo[12345]: ") from every line, across every _COMM= filter here -
so none of the regex patterns below expect that prefix. They match
only the raw message body that's left after journalctl strips it.
"""

import re
import subprocess
import threading
from datetime import datetime

from database.database import insert_event, insert_alert
from detector.privilege_escalation import detect_privilege_escalation


# ============================================================
# CONFIGURATION
# ============================================================

SERVER_LABEL = "central"


# ============================================================
# SUDO / SU PARSING
# ============================================================

def parse_sudo_su_line(log_line):

    # ---- Successful sudo command ----
    # Real line (after -o cat strips the "sudo[PID]:" prefix):
    #   root : TTY=pts/4 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/ls
    match = re.search(
        r"^\s*(\S+)\s*:\s*TTY=\S+\s*;\s*PWD=(\S+)\s*;"
        r"\s*USER=(\S+)\s*;\s*COMMAND=(.+)",
        log_line
    )

    if match:

        acting_user = match.group(1)
        target_user = match.group(3)
        command = match.group(4)

        return {
            "event_type": "sudo_command_executed",
            "source_ip": None,
            "username": acting_user,
            "severity": "medium",
            "message": (
                f"{acting_user} ran '{command}' as {target_user}: "
                f"{log_line.strip()}"
            )
        }


    # ---- Failed sudo attempt (wrong password entered) ----
    # Real line: "user : 3 incorrect password attempts ; TTY=... ;
    #             PWD=... ; USER=... ; COMMAND=..."
    match = re.search(
        r"^\s*(\S+)\s*:.*incorrect password attempt",
        log_line
    )

    if match:

        acting_user = match.group(1)

        return {
            "event_type": "sudo_failed_attempt",
            "source_ip": None,
            "username": acting_user,
            "severity": "high",
            "message": log_line.strip()
        }


    # ---- Failed sudo via PAM (alternate wording some systems use) ----
    # Real line: "pam_unix(sudo:auth): authentication failure; ...
    #             ruser=someuser ..."
    match = re.search(
        r"pam_unix\(sudo:auth\):\s*authentication failure.*ruser=(\S+)",
        log_line
    )

    if match:

        acting_user = match.group(1)

        return {
            "event_type": "sudo_failed_attempt",
            "source_ip": None,
            "username": acting_user,
            "severity": "high",
            "message": log_line.strip()
        }


    # ---- Successful su ----
    # Real line: "(to root) someuser on pts/0"
    match = re.search(
        r"\(to (\S+)\)\s*(\S+)\s*on",
        log_line
    )

    if match:

        target_user = match.group(1)
        acting_user = match.group(2)

        return {
            "event_type": "su_successful",
            "source_ip": None,
            "username": acting_user,
            "severity": "medium",
            "message": (
                f"{acting_user} switched to {target_user}: "
                f"{log_line.strip()}"
            )
        }


    # ---- Failed su ----
    # Real line: "pam_unix(su:auth): authentication failure; ...
    #             ruser=someuser ..."
    match = re.search(
        r"pam_unix\(su.*\):\s*authentication failure.*ruser=(\S+)",
        log_line
    )

    if match:

        acting_user = match.group(1)

        return {
            "event_type": "su_failed_attempt",
            "source_ip": None,
            "username": acting_user,
            "severity": "high",
            "message": log_line.strip()
        }


    return None



# ============================================================
# ACCOUNT CHANGE PARSING
# ============================================================

def parse_account_change_line(log_line):

    # Real line: "new user: name=bob, UID=1002, GID=1002, ..."
    match = re.search(
        r"new user:\s*name=(\S+?),",
        log_line
    )

    if match:

        new_username = match.group(1)

        return {
            "event_type": "user_account_created",
            "source_ip": None,
            "username": new_username,
            "severity": "high",
            "message": log_line.strip()
        }


    # Real line: "delete user 'bob'"
    match = re.search(
        r"delete user\s*'(\S+)'",
        log_line
    )

    if match:

        deleted_username = match.group(1)

        return {
            "event_type": "user_account_deleted",
            "source_ip": None,
            "username": deleted_username,
            "severity": "medium",
            "message": log_line.strip()
        }


    # Real line: "add 'bob' to group 'sudo'" (or similar usermod output)
    match = re.search(
        r"^(add|del|change).*",
        log_line
    )

    if match:

        return {
            "event_type": "user_account_modified",
            "source_ip": None,
            "username": None,
            "severity": "medium",
            "message": f"usermod: {log_line.strip()}"
        }


    # Real line: "new group: name=devops, GID=1003"
    match = re.search(
        r"new group:\s*name=(\S+?),",
        log_line
    )

    if match:

        new_group = match.group(1)

        return {
            "event_type": "group_created",
            "source_ip": None,
            "username": None,
            "severity": "medium",
            "message": f"New group created: {new_group}"
        }


    return None



# ============================================================
# CRON PARSING
# ============================================================

def parse_cron_line(log_line):
    """
    Matches crontab command invocations (crontab -e, crontab -r,
    etc.) - NOT cron job executions. Job executions just mean an
    already-scheduled job ran; what we want to catch is someone
    EDITING their crontab, the actual persistence-mechanism concern.
    """

    # Real line: "(root) REPLACE (root)" or "(root) BEGIN EDIT (root)"
    match = re.search(
        r"\(([^)]+)\)\s*(REPLACE|BEGIN EDIT|END EDIT)",
        log_line
    )

    if match:

        acting_user = match.group(1)
        action = match.group(2)

        return {
            "event_type": "cron_job_modified",
            "source_ip": None,
            "username": acting_user,
            "severity": "medium",
            "message": (
                f"{acting_user} modified their crontab ({action}): "
                f"{log_line.strip()}"
            )
        }


    return None



# ============================================================
# PROCESS A SINGLE LOG LINE
# ============================================================

def process_line(log_line, parser_function):

    event = parser_function(log_line)

    if event is None:
        return


    timestamp = datetime.now().isoformat(timespec="seconds")

    insert_event(
        timestamp=timestamp,
        event_type=event["event_type"],
        source_ip=event["source_ip"],
        username=event["username"],
        severity=event["severity"],
        message=event["message"],
        server_label=SERVER_LABEL
    )

    print(f"[{SERVER_LABEL}] {event['event_type']}: {event['message'][:80]}")


    # ---- Privilege escalation brute-force check ----

    if event["event_type"] in ("sudo_failed_attempt", "su_failed_attempt"):

        if event["username"]:

            alert = detect_privilege_escalation(
                username=event["username"],
                server_label=SERVER_LABEL
            )

            if alert:

                print(
                    f"[{SERVER_LABEL}] PRIVILEGE ESCALATION ALERT: "
                    f"{alert['description']}"
                )


    # ---- Immediate alert for account changes ----

    if event["event_type"] in ("user_account_created", "group_created"):

        insert_alert(
            timestamp=timestamp,
            alert_type=event["event_type"],
            source_ip=None,
            severity="high",
            description=event["message"],
            server_label=SERVER_LABEL
        )



# ============================================================
# TAIL A JOURNALCTL STREAM
# ============================================================

def tail_journalctl(match_args, parser_function, label):

    print(f"Watching journald ({label})...")

    # stdbuf -oL forces line-buffered output even though stdout is
    # a pipe (not a TTY) here. Without this, journalctl silently
    # block-buffers its output when piped, meaning lines can sit
    # unflushed for a long time instead of arriving in real time.
    command = (
        ["stdbuf", "-oL", "journalctl"]
        + match_args
        + ["-o", "cat", "-f", "-n", "0"]
    )

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    try:

        for line in process.stdout:

            line = line.strip()

            if line:
                process_line(line, parser_function)

    finally:

        process.terminate()



# ============================================================
# MAIN
# ============================================================

def monitor_auth_and_cron():

    print("Mini-SOC auth/cron monitor started (journald mode).")
    print(f"Server label: {SERVER_LABEL}")
    print("Press CTRL+C to stop.\n")

    threads = [

        threading.Thread(
            target=tail_journalctl,
            args=(
                ["_COMM=sudo", "_COMM=su"],
                parse_sudo_su_line,
                "sudo/su"
            ),
            daemon=True
        ),

        threading.Thread(
            target=tail_journalctl,
            args=(
                [
                    "_COMM=useradd", "_COMM=usermod",
                    "_COMM=groupadd", "_COMM=userdel", "_COMM=groupdel"
                ],
                parse_account_change_line,
                "account changes"
            ),
            daemon=True
        ),

        threading.Thread(
            target=tail_journalctl,
            args=(
                ["_COMM=crontab"],
                parse_cron_line,
                "cron modifications"
            ),
            daemon=True
        ),

    ]

    for thread in threads:
        thread.start()

    try:

        for thread in threads:
            thread.join()

    except KeyboardInterrupt:

        print("\nStopping auth/cron monitor...")



if __name__ == "__main__":
    monitor_auth_and_cron()