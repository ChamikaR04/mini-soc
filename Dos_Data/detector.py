from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import threading
import time
import subprocess
import sys
import json
import os
import sqlite3
from datetime import datetime



#============================================================
#CONECTIVITY CHECK
#============================================================

def is_server_reachable(ip, timeout=2):
    result = subprocess.run(
        ["ping", "-c", "1", "-W", str(timeout), ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0


# ============================================================
# CONFIGURATION
# ============================================================

# Put the IP address of the server you want to monitor
SERVER_IP = "172.105.44.186"


# Analyze traffic every 10 seconds
ANALYSIS_INTERVAL = 10


# Separate DB file from soc.db so the two processes never
# lock/contend with each other.
DB_PATH = "/opt/mini-soc/Dos_Data/traffic.db"

# Kept for backwards compatibility / quick external tools
# that might still want the plain JSON snapshot.
RESULT_PATH = "/opt/mini-soc/Dos_Data/ddos_status.json"


# ============================================================
# DETECTION THRESHOLDS
# These values are packets PER SECOND
# Adjust them later after measuring normal traffic
# ============================================================

SYN_THRESHOLD = 200
UDP_THRESHOLD = 500
ICMP_THRESHOLD = 500
TOTAL_THRESHOLD = 2000
SOURCE_THRESHOLD = 1000
DDOS_SOURCE_THRESHOLD = 10
SUSPICIOUS_SOURCE_RATE = 100


# ============================================================
# TRAFFIC COUNTERS
# ============================================================

stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "syn": 0,
}


# Packets from each source IP
source_packets = defaultdict(int)

# Destination ports receiving traffic
tcp_ports = defaultdict(int)
udp_ports = defaultdict(int)

# Buffer of individual packet records, flushed to the DB
# once per analysis cycle instead of one write per packet.
packet_buffer = []

lock = threading.Lock()


# ============================================================
# DATABASE SETUP
# ============================================================

def get_connection():
    return sqlite3.connect(DB_PATH)


def initialize_database():

    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    connection = get_connection()
    cursor = connection.cursor()

    # One row per captured packet
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            protocol TEXT,
            destination_port INTEGER
        )
    """)

    # One row per analysis cycle (10s snapshot)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ddos_status (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            server_ip TEXT,
            threat_level TEXT,
            total_rate REAL,
            tcp_rate REAL,
            udp_rate REAL,
            icmp_rate REAL,
            syn_rate REAL,
            active_sources INTEGER,
            top_sources TEXT,
            suspicious_sources TEXT,
            alerts TEXT
        )
    """)

    connection.commit()
    connection.close()


def flush_packet_buffer_to_db(buffer):
    """
    Batched insert of every packet captured during the last
    analysis interval. Called once per cycle, not per packet,
    to keep packet capture fast.
    """

    if not buffer:
        return

    connection = get_connection()
    cursor = connection.cursor()

    cursor.executemany("""
        INSERT INTO traffic_log
        (timestamp, source_ip, protocol, destination_port)
        VALUES (?, ?, ?, ?)
    """, buffer)

    connection.commit()
    connection.close()


def insert_ddos_status(result):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO ddos_status
        (timestamp, server_ip, threat_level,
         total_rate, tcp_rate, udp_rate, icmp_rate, syn_rate,
         active_sources, top_sources, suspicious_sources, alerts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        result["timestamp"],
        result["server_ip"],
        result["threat_level"],
        result["rates"]["total"],
        result["rates"]["tcp"],
        result["rates"]["udp"],
        result["rates"]["icmp"],
        result["rates"]["syn"],
        result["active_sources"],
        json.dumps(result["top_sources"]),
        json.dumps(result["suspicious_sources"]),
        json.dumps(result["alerts"]),
    ))

    connection.commit()
    connection.close()


def write_result_json(result):
    """
    Optional: keep writing the plain JSON snapshot too, in case
    anything else still reads it. Safe to remove if you only
    want the DB going forward.
    """

    os.makedirs(os.path.dirname(RESULT_PATH), exist_ok=True)

    tmp_path = RESULT_PATH + ".tmp"

    with open(tmp_path, "w") as f:
        json.dump(result, f, indent=2)

    os.replace(tmp_path, RESULT_PATH)


# ============================================================
# PROCESS PACKETS
# ============================================================

def process_packet(packet):

    # Ignore packets that do not contain IPv4
    if IP not in packet:
        return

    # Only monitor packets coming INTO the selected server
    if packet[IP].dst != SERVER_IP:
        return

    src_ip = packet[IP].src
    timestamp = datetime.now().isoformat(timespec="seconds")

    with lock:

        stats["total"] += 1

        # Count traffic from each source IP
        source_packets[src_ip] += 1

        protocol = None
        destination_port = None


        # ====================================================
        # TCP
        # ====================================================

        if TCP in packet:

            stats["tcp"] += 1
            protocol = "TCP"

            destination_port = packet[TCP].dport

            tcp_ports[destination_port] += 1

            flags = packet[TCP].flags

            # SYN without ACK usually represents
            # a new TCP connection attempt
            if (flags & 0x02) and not (flags & 0x10):

                stats["syn"] += 1


        # ====================================================
        # UDP
        # ====================================================

        elif UDP in packet:

            stats["udp"] += 1
            protocol = "UDP"

            destination_port = packet[UDP].dport

            udp_ports[destination_port] += 1


        # ====================================================
        # ICMP
        # ====================================================

        elif ICMP in packet:

            stats["icmp"] += 1
            protocol = "ICMP"


        # Queue this packet for batched DB insert
        packet_buffer.append((
            timestamp,
            src_ip,
            protocol,
            destination_port
        ))


# ============================================================
# DISPLAY TOP PORTS
# ============================================================

def display_top_ports(port_dictionary, limit=5):

    if not port_dictionary:

        print("None")

        return

    sorted_ports = sorted(
        port_dictionary.items(),
        key=lambda item: item[1],
        reverse=True
    )

    for port, count in sorted_ports[:limit]:

        rate = count / ANALYSIS_INTERVAL

        print(
            f"Port {port:<6} "
            f"{rate:.2f} pkt/sec"
        )


# ============================================================
# ANALYZE TRAFFIC
# ============================================================

def analyze_traffic():

    while True:

        time.sleep(ANALYSIS_INTERVAL)

        with lock:

            # Get packet totals collected during the interval
            total = stats["total"]
            tcp = stats["tcp"]
            udp = stats["udp"]
            icmp = stats["icmp"]
            syn = stats["syn"]


            # =================================================
            # CONVERT COUNTS INTO PACKETS PER SECOND
            # =================================================

            total_rate = total / ANALYSIS_INTERVAL
            tcp_rate = tcp / ANALYSIS_INTERVAL
            udp_rate = udp / ANALYSIS_INTERVAL
            icmp_rate = icmp / ANALYSIS_INTERVAL
            syn_rate = syn / ANALYSIS_INTERVAL


            # =================================================
            # FIND TOP SOURCE IP
            # =================================================

            sorted_sources = sorted(
                source_packets.items(),
                key=lambda item: item[1],
                reverse=True
            )

            top_sources = sorted_sources[:10]

            # Number of unique source IPs seen in this interval
            active_sources = len(source_packets)

            # Sources sending traffic above the suspicious per-source rate
            suspicious_sources = []

            for ip, count in source_packets.items():
                rate = count / ANALYSIS_INTERVAL

                if rate >= SUSPICIOUS_SOURCE_RATE:
                    suspicious_sources.append((ip, rate))

            suspicious_sources.sort(
                key=lambda item: item[1],
                reverse=True
            )


            # =================================================
            # DISPLAY TRAFFIC INFORMATION
            # =================================================

            print("\n")
            print("=" * 55)
            print("            DOS / DDOS DETECTOR")
            print("=" * 55)

            print(f"Server IP          : {SERVER_IP}")
            
            print(
                f"Analysis Interval  : "
                f"{ANALYSIS_INTERVAL} seconds"
            )

            print("-" * 55)

            print("TRAFFIC RATE")

            print("-" * 55)

            print(
                f"Total packets/sec  : "
                f"{total_rate:.2f}"
            )

            print(
                f"TCP packets/sec    : "
                f"{tcp_rate:.2f}"
            )

            print(
                f"UDP packets/sec    : "
                f"{udp_rate:.2f}"
            )

            print(
                f"ICMP packets/sec   : "
                f"{icmp_rate:.2f}"
            )

            print(
                f"SYN packets/sec    : "
                f"{syn_rate:.2f}"
            )


            # =================================================
            # SOURCE INFORMATION
            # =================================================

            print("-" * 55)

            print("TOP SOURCE IPs")

            print("-" * 55)

            if top_sources:
                for ip,count in top_sources:
                    rate = count / ANALYSIS_INTERVAL

                    print(
                        f"{ip:<18} "
                        f"{rate:>10.2f} pkt/sec"
                    )
            else:
                print("None")

            print(
                f"Active Source IPs  : "
                f"{active_sources}"
            )

            # =================================================
            # TCP PORTS
            # =================================================

            print("-" * 55)

            print("TOP TCP DESTINATION PORTS")

            print("-" * 55)

            display_top_ports(
                tcp_ports
            )


            # =================================================
            # UDP PORTS
            # =================================================

            print("-" * 55)

            print("TOP UDP DESTINATION PORTS")

            print("-" * 55)

            display_top_ports(
                udp_ports
            )

            # =================================================
            # SUSPICIOUS SOURCES
            # =================================================

            print("-" * 55)
            print("SUSPICIOUS SOURCE IPS")
            print("-" * 55)

            if suspicious_sources:

                for ip, rate in suspicious_sources[:10]:

                    print(
                        f"{ip:<18} "
                        f"{rate:>10.2f} pkt/sec"
                    )

            else:

                print("None")


            # =================================================
            # THREAT DETECTION
            # =================================================

            alerts = []


            # SYN Flood Detection
            if syn_rate > SYN_THRESHOLD:

                alerts.append(
                    "Possible TCP SYN Flood"
                )


            # UDP Flood Detection
            if udp_rate > UDP_THRESHOLD:

                alerts.append(
                    "Possible UDP Flood"
                )


            # ICMP Flood Detection
            if icmp_rate > ICMP_THRESHOLD:

                alerts.append(
                    "Possible ICMP Flood"
                )


            # Overall traffic spike
            if total_rate > TOTAL_THRESHOLD:

                alerts.append(
                    "Very High Traffic Volume"
                )


            # Check every source IP for unusually high traffic
            high_rate_sources = []

            for ip, count in source_packets.items():

                rate = count / ANALYSIS_INTERVAL

                if rate > SOURCE_THRESHOLD:

                    high_rate_sources.append((ip, rate))

                    alerts.append(
                        f"High Traffic From {ip} "
                        f"({rate:.2f} pkt/sec)"
                    )

            # Possible distributed attack:
            # high total traffic coming from many unique source IPs
            if (
                total_rate > TOTAL_THRESHOLD
                and active_sources >= DDOS_SOURCE_THRESHOLD
            ):

                alerts.append(
                    f"Possible DDoS - "
                    f"{active_sources} active source IPs"
                )

            # Many sources individually sending suspicious traffic
            if len(suspicious_sources) >= DDOS_SOURCE_THRESHOLD:

                alerts.append(
                    f"Possible Distributed Attack - "
                    f"{len(suspicious_sources)} high-rate sources"
                )


            # =================================================
            # THREAT LEVEL
            # =================================================

            if len(alerts) == 0:

                threat_level = "NORMAL"

            elif len(alerts) == 1:

                threat_level = "WARNING"

            else:

                threat_level = "CRITICAL"


            # =================================================
            # DISPLAY DETECTION RESULT
            # =================================================

            print("-" * 55)

            print("DETECTION RESULT")

            print("-" * 55)

            print(
                f"Threat Level       : "
                f"{threat_level}"
            )

            if alerts:

                print("Alerts:")

                for alert in alerts:

                    print(
                        f"  - {alert}"
                    )

            else:

                print(
                    "Alerts             : None"
                )

            print("=" * 55)


            # =================================================
            # BUILD RESULT SNAPSHOT
            # =================================================

            result = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "server_ip": SERVER_IP,
                "threat_level": threat_level,
                "rates": {
                    "total": round(total_rate, 2),
                    "tcp": round(tcp_rate, 2),
                    "udp": round(udp_rate, 2),
                    "icmp": round(icmp_rate, 2),
                    "syn": round(syn_rate, 2),
                },
                "active_sources": active_sources,
                "top_sources": [
                    {
                        "ip": ip,
                        "rate": round(count / ANALYSIS_INTERVAL, 2)
                    }
                    for ip, count in top_sources
                ],
                "suspicious_sources": [
                    {
                        "ip": ip,
                        "rate": round(rate, 2)
                    }
                    for ip, rate in suspicious_sources[:10]
                ],
                "alerts": alerts
            }


            # =================================================
            # PERSIST TO DATABASE
            # =================================================

            try:
                # All packets captured this interval, batched
                # into a single insert.
                flush_packet_buffer_to_db(packet_buffer)
                packet_buffer.clear()

                # This cycle's threat snapshot.
                insert_ddos_status(result)

            except Exception as db_error:
                print(f"Failed to write to database: {db_error}")

            # Optional plain JSON snapshot, kept for compatibility.
            try:
                write_result_json(result)
            except Exception as write_error:
                print(f"Failed to write DDoS status JSON: {write_error}")


            # =================================================
            # RESET COUNTERS
            # =================================================

            stats["total"] = 0
            stats["tcp"] = 0
            stats["udp"] = 0
            stats["icmp"] = 0
            stats["syn"] = 0

            source_packets.clear()

            tcp_ports.clear()
            udp_ports.clear()


# ============================================================
# START ANALYSIS THREAD
# ============================================================

initialize_database()

print("Checking server connectivity...")
if not is_server_reachable(SERVER_IP):
    print("Server is not reachable.")
    sys.exit(1)

print("Server is reachable. Starting traffic analysis thread...")

analysis_thread = threading.Thread(
    target=analyze_traffic,
    daemon=True
)

analysis_thread.start()


# ============================================================
# START PACKET CAPTURE
# ============================================================

print("=" * 55)
print("       Starting DoS / DDoS Detector")
print("=" * 55)

print(
    f"Monitoring Server : {SERVER_IP}"
)

print(
    f"Database           : {DB_PATH}"
)



print(
    "Press CTRL+C to stop."
)

print("=" * 55)


try:

    sniff(
    filter=f"dst host {SERVER_IP}",
    prn=process_packet,
    store=False
)


except KeyboardInterrupt:

    print(
        "\nDoS Detector stopped."
    )

    # Flush anything left in the buffer before exiting
    with lock:
        try:
            flush_packet_buffer_to_db(packet_buffer)
            packet_buffer.clear()
        except Exception as final_flush_error:
            print(f"Failed to flush remaining packets: {final_flush_error}")


except PermissionError:

    print(
        "\nPermission denied."
    )

    print(
        "Run using:"
    )

    print(
        "sudo python3 detector.py"
    )


except Exception as error:

    print(
        f"\nError: {error}"
    )
