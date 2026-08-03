from db import get_recent_logs, insert_log

def correlate(source: str):
    """
    Returns a list of (severity, message) for any correlation alerts created.
    """
    generated = []

    # Look back 60s
    recent = get_recent_logs(source, seconds=60)
    severities = [r[2] for r in recent]

    # Rule 1: USB_INSERT + PROCESS within 30 seconds => HIGH
    recent30 = get_recent_logs(source, seconds=30)
    types30 = [r[0] for r in recent30]

    if ("USB_INSERT" in types30) and ("PROCESS" in types30):
        msg = "Correlation: USB inserted and new process detected within 30 seconds (possible malicious execution)."
        insert_log(source, "CORR", msg, "HIGH")
        generated.append(("HIGH", msg))

    # Rule 2: 5+ LOW events in 60 seconds => MEDIUM
    low_count = sum(1 for s in severities if s == "LOW")
    if low_count >= 5:
        msg = f"Correlation: Burst activity detected ({low_count} LOW events in 60s)."
        insert_log(source, "CORR", msg, "MEDIUM")
        generated.append(("MEDIUM", msg))

    return generated
