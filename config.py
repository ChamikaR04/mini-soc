# ============================================================
# config.py
#
# All the settings you actually need to touch for THIS
# server's detector are here, in one place.
# ============================================================

# The IP address this detector should watch traffic for.
# Usually this server's own IP, unless you're monitoring
# something else it can see.
SERVER_IP = "172.236.181.123"  # e.g. "192.168.1.50"

# How often (in seconds) to analyze traffic and send a snapshot.
ANALYSIS_INTERVAL = 10

# The central dashboard server's ingest endpoint.
CENTRAL_SERVER_URL = "http://100.103.159.16:5000/api/ddos-ingest"

# Must match INGEST_API_KEY in app.py on the central server.
# Generate a long random string, e.g.:
#   python3 -c "import secrets; print(secrets.token_hex(32))"
INGEST_API_KEY = "03c7b32c03de3c8d8b8a62276d1c6ce430c39f78770df33fd6704e320d29686e"

# Optional: identifies which server this snapshot came from,
# useful once you have more than one remote detector reporting
# to the same central dashboard.
SERVER_LABEL = "SCADA-Server"

# Detection thresholds (packets per second).
SYN_THRESHOLD = 200
UDP_THRESHOLD = 500
ICMP_THRESHOLD = 500
TOTAL_THRESHOLD = 2000
SOURCE_THRESHOLD = 1000
DDOS_SOURCE_THRESHOLD = 10
SUSPICIOUS_SOURCE_RATE = 100

# Keep a local copy too, in case the network to the central
# server is temporarily down. Set to None to disable.
LOCAL_BACKUP_PATH = "/opt/remote-detector/ddos_status.json"

# HTTP request timeout (seconds) when sending to the central server.
REQUEST_TIMEOUT = 5
