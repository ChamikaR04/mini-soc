from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import threading
import time
import subprocess
import sys
import json
import os
import requests
from datetime import datetime

from config import (
    SERVER_IP,
    ANALYSIS_INTERVAL,
    CENTRAL_SERVER_URL,
    INGEST_API_KEY,
    SERVER_LABEL,
    SYN_THRESHOLD,
    UDP_THRESHOLD,
    ICMP_THRESHOLD,
    TOTAL_THRESHOLD,
    SOURCE_THRESHOLD,
    DDOS_SOURCE_THRESHOLD,
    SUSPICIOUS_SOURCE_RATE,
    LOCAL_BACKUP_PATH,
    REQUEST_TIMEOUT,
)


# ============================================================
# CONNECTIVITY CHECK
# ============================================================

def is_server_reachable(ip, timeout=2):
    result = subprocess.run(
        ["ping", "-c", "1", "-W", str(timeout), ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0


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

source_packets = defaultdict(int)
tcp_ports = defaultdict(int)
udp_ports = defaultdict(int)

lock = threading.Lock()


# ============================================================
# SEND RESULT TO CENTRAL SERVER
# ============================================================

def send_result_to_central_server(result):

    try:
        response = requests.post(
            CENTRAL_SERVER_URL,
            json=result,
            headers={"X-API-Key": INGEST_API_KEY},
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 200:
            print(
                f"[{result['threat_level']}] "
                f"Snapshot sent to central server."
            )
        else:
            print(
                f"Central server rejected snapshot: "
                f"{response.status_code} {response.text}"
            )

    except requests.exceptions.RequestException as error:
        print(f"Failed to send snapshot to central server: {error}")


# ============================================================
# OPTIONAL LOCAL BACKUP
# Keeps a copy on disk in case the network to the central
# server is temporarily unreachable.
# ============================================================

def write_local_backup(result):

    if not LOCAL_BACKUP_PATH:
        return

    os.makedirs(os.path.dirname(LOCAL_BACKUP_PATH), exist_ok=True)

    tmp_path = LOCAL_BACKUP_PATH + ".tmp"

    with open(tmp_path, "w") as f:
        json.dump(result, f, indent=2)

    os.replace(tmp_path, LOCAL_BACKUP_PATH)


# ============================================================
# PROCESS PACKETS
# ============================================================

def process_packet(packet):

    if IP not in packet:
        return

    if packet[IP].dst != SERVER_IP:
        return

    src_ip = packet[IP].src

    with lock:

        stats["total"] += 1
        source_packets[src_ip] += 1

        if TCP in packet:

            stats["tcp"] += 1
            destination_port = packet[TCP].dport
            tcp_ports[destination_port] += 1

            flags = packet[TCP].flags

            if (flags & 0x02) and not (flags & 0x10):
                stats["syn"] += 1

        elif UDP in packet:

            stats["udp"] += 1
            destination_port = packet[UDP].dport
            udp_ports[destination_port] += 1

        elif ICMP in packet:

            stats["icmp"] += 1


# ============================================================
# ANALYZE TRAFFIC
# ============================================================

def analyze_traffic():

    while True:

        time.sleep(ANALYSIS_INTERVAL)

        with lock:

            total = stats["total"]
            tcp = stats["tcp"]
            udp = stats["udp"]
            icmp = stats["icmp"]
            syn = stats["syn"]

            total_rate = total / ANALYSIS_INTERVAL
            tcp_rate = tcp / ANALYSIS_INTERVAL
            udp_rate = udp / ANALYSIS_INTERVAL
            icmp_rate = icmp / ANALYSIS_INTERVAL
            syn_rate = syn / ANALYSIS_INTERVAL

            sorted_sources = sorted(
                source_packets.items(),
                key=lambda item: item[1],
                reverse=True
            )

            top_sources = sorted_sources[:10]
            active_sources = len(source_packets)

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
            # THREAT DETECTION
            # =================================================

            alerts = []

            if syn_rate > SYN_THRESHOLD:
                alerts.append("Possible TCP SYN Flood")

            if udp_rate > UDP_THRESHOLD:
                alerts.append("Possible UDP Flood")

            if icmp_rate > ICMP_THRESHOLD:
                alerts.append("Possible ICMP Flood")

            if total_rate > TOTAL_THRESHOLD:
                alerts.append("Very High Traffic Volume")

            for ip, count in source_packets.items():

                rate = count / ANALYSIS_INTERVAL

                if rate > SOURCE_THRESHOLD:
                    alerts.append(
                        f"High Traffic From {ip} "
                        f"({rate:.2f} pkt/sec)"
                    )

            if (
                total_rate > TOTAL_THRESHOLD
                and active_sources >= DDOS_SOURCE_THRESHOLD
            ):
                alerts.append(
                    f"Possible DDoS - "
                    f"{active_sources} active source IPs"
                )

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
            # TERMINAL OUTPUT (kept minimal for a remote sensor)
            # =================================================

            print(
                f"[{SERVER_LABEL}] "
                f"{datetime.now().isoformat(timespec='seconds')} "
                f"| total={total_rate:.2f} pkt/s "
                f"| threat={threat_level}"
            )


            # =================================================
            # BUILD RESULT SNAPSHOT
            # =================================================

            result = {
                "server_label": SERVER_LABEL,
                "server": SERVER_LABEL,
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
            # SEND TO CENTRAL SERVER + LOCAL BACKUP
            # =================================================

            send_result_to_central_server(result)

            try:
                write_local_backup(result)
            except Exception as backup_error:
                print(f"Failed to write local backup: {backup_error}")


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
# START
# ============================================================

print("Checking server connectivity...")
if not is_server_reachable(SERVER_IP):
    print(f"Warning: {SERVER_IP} did not respond to ping (continuing anyway).")

print(f"Remote detector '{SERVER_LABEL}' starting.")
print(f"Monitoring         : {SERVER_IP}")
print(f"Sending results to : {CENTRAL_SERVER_URL}")
print("Press CTRL+C to stop.")

analysis_thread = threading.Thread(target=analyze_traffic, daemon=True)
analysis_thread.start()

try:

    sniff(
        filter=f"dst host {SERVER_IP}",
        prn=process_packet,
        store=False
    )

except KeyboardInterrupt:
    print("\nRemote detector stopped.")

except PermissionError:
    print("\nPermission denied. Run using: sudo python3 detector.py")

except Exception as error:
    print(f"\nError: {error}")