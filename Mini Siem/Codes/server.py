import socket
import json
 
from db import insert_log, upsert_endpoint
from detection import analyze_log
from ir_guidance import get_guidance
from correlation import correlate

HOST = "0.0.0.0"
PORT = 9999
 
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen()
 
print("[Mini-SIEM] Listening for agents...")
 
 
def safe_recv_all(client, max_bytes=65535):
    data = client.recv(max_bytes)
    return data.decode(errors="ignore")


while True:
    client, addr = server.accept()
    try:
        raw = safe_recv_all(client)
        log = json.loads(raw)

        source = log.get("source", "UNKNOWN")
        log_type = (log.get("type") or "UNKNOWN").upper()
        message = log.get("message", "")
        os_name = log.get("os", "unknown")
 
        # Update endpoint (connected devices feature)
        upsert_endpoint(source, ip=str(addr[0]), os_name=os_name)

        # If heartbeat: store as INFO (or skip storing if you want)
        if log_type == "HEARTBEAT":
            insert_log(source, log_type, message or "Heartbeat received", "INFO")
            client.close()
            continue

        severity = analyze_log(log_type, message)
        insert_log(source, log_type, message, severity)

        print(f"\nLog from {source} ({addr[0]}) | {log_type} | {severity}")
        print(message)

        # Correlation after each log
        new_alerts = correlate(source)

        # Print guidance for correlation alerts too
        for sev, msg in new_alerts:
            print(f"\n[CORRELATED ALERT] {source} | {sev}")
            print(msg)
            print(get_guidance(sev))

    finally:
        client.close()
