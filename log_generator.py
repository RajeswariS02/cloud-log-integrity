import datetime
from hash_utils import generate_hash

# Map each event to a severity level
SEVERITY_MAP = {
    "User login":         "INFO",
    "File uploaded":      "INFO",
    "File deleted":       "WARNING",
    "Permission changed": "WARNING",
    "Auto Event":         "INFO",
    "Unauthorized access attempt": "CRITICAL",
    "Config modified":    "CRITICAL",
    "Service restarted":  "WARNING",
}

def get_severity(event):
    return SEVERITY_MAP.get(event, "INFO")

def create_log(event, prev_hash):
    timestamp = str(datetime.datetime.now())
    data = timestamp + event + prev_hash
    current_hash = generate_hash(data)

    return {
        "timestamp": timestamp,
        "event": event,
        "severity": get_severity(event),
        "previous_hash": prev_hash,
        "current_hash": current_hash
    }