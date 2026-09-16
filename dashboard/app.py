
from flask import Flask, render_template, jsonify, request
import sqlite3
from datetime import datetime, timedelta
import json
import os
from detector.detection_engine import determine_severity


app = Flask(__name__)

DATABASE = "/opt/mini-soc/database/soc.db"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DDOS_STATUS_PATH = os.path.join(
    BASE_DIR,
    "Dos_Data",
    "ddos_status.json"
)

DDOS_SERVERS_DIR = "/opt/mini-soc/Dos_Data/servers"


def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


@app.route("/minisoc")
def dashboard():
    return render_template("dashboard.html")


# ============================================================
# SERVER LIST
# ============================================================

@app.route("/api/servers")
def servers_list():

    labels = set()

    # Servers that have DoS/DDoS status files
    if os.path.exists(DDOS_SERVERS_DIR):

        for filename in os.listdir(DDOS_SERVERS_DIR):

            if filename.endswith(".json"):
                labels.add(filename[:-5])

    # Servers stored in database
    db = get_db()

    rows = db.execute("""
        SELECT DISTINCT server_label
        FROM events
        WHERE server_label IS NOT NULL
        AND server_label != ''
    """).fetchall()

    for row in rows:
        labels.add(row["server_label"])

    rows = db.execute("""
        SELECT DISTINCT server_label
        FROM alerts
        WHERE server_label IS NOT NULL
        AND server_label != ''
    """).fetchall()

    for row in rows:
        labels.add(row["server_label"])

    db.close()

    if not labels:
        labels.add("central")

    return jsonify(sorted(labels))


# ============================================================
# OVERVIEW STATS
# ============================================================

@app.route("/api/stats")
def stats():

    server = request.args.get("server", "central")

    db = get_db()

    total_events = db.execute("""
        SELECT COUNT(*)
        FROM events
        WHERE server_label = ?
    """, (server,)).fetchone()[0]

    total_alerts = db.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE server_label = ?
    """, (server,)).fetchone()[0]

    high_alerts = db.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE server_label = ?
        AND severity = 'high'
    """, (server,)).fetchone()[0]

    open_alerts = db.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE server_label = ?
        AND status = 'open'
    """, (server,)).fetchone()[0]

    db.close()

    return jsonify({
        "server": server,
        "total_events": total_events,
        "total_alerts": total_alerts,
        "high_alerts": high_alerts,
        "open_alerts": open_alerts
    })


# ============================================================
# EVENTS
# ============================================================

# ============================================================
# SSH EVENT INGEST (from remote sensors)
# ============================================================

@app.route("/api/ssh-ingest", methods=["POST"])
def ssh_ingest():

    provided_key = request.headers.get("X-API-Key")

    if provided_key != INGEST_API_KEY:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(silent=True)

    if data is None:
        return jsonify({"error": "invalid or missing JSON body"}), 400

    server_label = data.get("server_label", "central")
    timestamp = data.get("timestamp") or datetime.now().isoformat(timespec="seconds")
    event_type = data.get("event_type")
    source_ip = data.get("source_ip")
    username = data.get("username")
    severity = data.get("severity")
    message = data.get("message")

    if not event_type:
        return jsonify({"error": "event_type is required"}), 400

    db = get_db()

    db.execute("""
        INSERT INTO events
        (timestamp, event_type, source_ip, username, severity, message, server_label)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp, event_type, source_ip, username, severity, message, server_label
    ))

    db.commit()

    alert_created = None

    if event_type == "ssh_failed_login" and source_ip:
        alert_created = ssh_ingest_detect_bruteforce(db, source_ip, server_label)

    db.close()

    return jsonify({
        "status": "received",
        "server_label": server_label,
        "alert": alert_created
    })


def ssh_ingest_detect_bruteforce(db, source_ip, server_label):

    FAILED_LOGIN_THRESHOLD = 15
    TIME_WINDOW_MINUTES = 2

    now = datetime.now()
    current_time = now.isoformat(timespec="seconds")

    cutoff_time = (
        now - timedelta(minutes=TIME_WINDOW_MINUTES)
    ).isoformat(timespec="seconds")

    failed_attempts = db.execute("""
        SELECT COUNT(*)
        FROM events
        WHERE event_type = 'ssh_failed_login'
        AND source_ip = ?
        AND server_label = ?
        AND timestamp >= ?
    """, (source_ip, server_label, cutoff_time)).fetchone()[0]

    if failed_attempts < FAILED_LOGIN_THRESHOLD:
        return None

    existing_alert = db.execute("""
        SELECT id, attempt_count, first_seen
        FROM alerts
        WHERE alert_type = 'ssh_bruteforce'
        AND source_ip = ?
        AND server_label = ?
        AND status = 'open'
        ORDER BY id DESC
        LIMIT 1
    """, (source_ip, server_label)).fetchone()

    if existing_alert:

        alert_id = existing_alert[0]
        previous_count = existing_alert[1] or 0
        first_seen = existing_alert[2] or current_time

        new_count = max(previous_count, failed_attempts)
        new_severity = determine_severity(new_count)

        description = (
            f"{new_count} failed SSH login attempts "
            f"detected from {source_ip}. "
            f"First seen: {first_seen}. "
            f"Last seen: {current_time}."
        )

        db.execute("""
            UPDATE alerts
            SET attempt_count = ?, last_seen = ?, description = ?, severity = ?
            WHERE id = ?
        """, (new_count, current_time, description, new_severity, alert_id))

        db.commit()
        return None

    description = (
        f"{failed_attempts} failed SSH login attempts "
        f"detected from {source_ip} within "
        f"{TIME_WINDOW_MINUTES} minutes."
    )
    severity = determine_severity(failed_attempts)
    db.execute("""
        INSERT INTO alerts
        (timestamp, alert_type, source_ip, severity, description,
         status, attempt_count, first_seen, last_seen, server_label)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        current_time, "ssh_bruteforce", source_ip, severity, description,
        "open", failed_attempts, current_time, current_time, server_label
    ))

    db.commit()

    return {
        "alert_type": "ssh_bruteforce",
        "source_ip": source_ip,
        "severity": severity,
        "description": description
    }


# ============================================================
@app.route("/api/events")
def events():

    server = request.args.get("server", "central")

    db = get_db()

    rows = db.execute("""
        SELECT
            id,
            timestamp,
            event_type,
            source_ip,
            username,
            severity,
            message,
            server_label
        FROM events
        WHERE server_label = ?
        ORDER BY id DESC
        LIMIT 20
    """, (server,)).fetchall()

    db.close()

    return jsonify([dict(row) for row in rows])


# ============================================================
# ALERTS
# ============================================================

@app.route("/api/alerts")
def alerts():

    server = request.args.get("server", "central")

    db = get_db()

    rows = db.execute("""
        SELECT
            id,
            timestamp,
            alert_type,
            source_ip,
            severity,
            description,
            status,
            attempt_count,
            first_seen,
            last_seen,
            server_label
        FROM alerts
        WHERE server_label = ?
        ORDER BY id DESC
        LIMIT 20
    """, (server,)).fetchall()

    db.close()

    return jsonify([dict(row) for row in rows])


# ============================================================
# DOS / DDOS STATUS
# ============================================================

@app.route("/api/ddos-status")
def ddos_status():

    server = request.args.get("server", "central")

    # --------------------------------------------------------
    # First try server-specific file
    # Example:
    # /opt/mini-soc/Dos_Data/servers/remote1.json
    # --------------------------------------------------------

    server_file = os.path.join(
        DDOS_SERVERS_DIR,
        f"{server}.json"
    )

    if os.path.exists(server_file):

        try:

            with open(server_file, "r") as f:
                data = json.load(f)

            return jsonify(data)

        except Exception as e:

            return jsonify({
                "status": "error",
                "error": str(e)
            }), 500

    # --------------------------------------------------------
    # Central/main server fallback
    # --------------------------------------------------------

    if server == "central" and os.path.exists(DDOS_STATUS_PATH):

        try:

            with open(DDOS_STATUS_PATH, "r") as f:
                data = json.load(f)

            return jsonify(data)

        except Exception as e:

            return jsonify({
                "status": "error",
                "error": str(e)
            }), 500

    # --------------------------------------------------------
    # No data for selected server
    # --------------------------------------------------------

    return jsonify({
        "status": "no_data",
        "server": server
    })


# ============================================================
# DDOS INGEST
# ============================================================

INGEST_API_KEY = "03c7b32c03de3c8d8b8a62276d1c6ce430c39f78770df33fd6704e320d29686e"


@app.route("/api/ddos-ingest", methods=["POST"])
def ddos_ingest():

    provided_key = request.headers.get("X-API-Key")

    if provided_key != INGEST_API_KEY:
        return jsonify({
            "error": "unauthorized"
        }), 401

    data = request.get_json(silent=True)

    if data is None:
        return jsonify({
            "error": "invalid or missing JSON body"
        }), 400

    # --------------------------------------------------------
    # Get server name from JSON or header
    # --------------------------------------------------------

    server = (
        data.get("server")
        or request.headers.get("X-Server")
        or "central"
    )

    data["server"] = server

    os.makedirs(
        DDOS_SERVERS_DIR,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Save server-specific status
    # --------------------------------------------------------

    server_path = os.path.join(
        DDOS_SERVERS_DIR,
        f"{server}.json"
    )

    tmp_path = server_path + ".tmp"

    with open(tmp_path, "w") as f:
        json.dump(
            data,
            f,
            indent=2
        )

    os.replace(
        tmp_path,
        server_path
    )

    # --------------------------------------------------------
    # Keep central file for backward compatibility
    # --------------------------------------------------------

    if server == "central":

        os.makedirs(
            os.path.dirname(DDOS_STATUS_PATH),
            exist_ok=True
        )

        tmp_path = DDOS_STATUS_PATH + ".tmp"

        with open(tmp_path, "w") as f:
            json.dump(
                data,
                f,
                indent=2
            )

        os.replace(
            tmp_path,
            DDOS_STATUS_PATH
        )

    return jsonify({
        "status": "received",
        "server": server
    }), 200


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
