def get_guidance(level):
    responses = {
        "HIGH": """[HIGH INCIDENT RESPONSE]
1. Immediately isolate the endpoint from network
2. Block suspicious IP at firewall (if applicable)
3. Capture volatile evidence (RAM, processes, network connections)
4. Begin forensic analysis and preserve logs""",

        "MEDIUM": """[MEDIUM INCIDENT RESPONSE]
1. Validate the event (file changes / anomaly cause)
2. Run antivirus/EDR scan
3. Review user activity and permissions
4. Monitor for escalation""",

        "LOW": """[LOW INCIDENT RESPONSE]
1. Monitor the activity
2. Confirm if legitimate (whitelist if verified)"""
    }

    return responses.get(level, "No action required")
