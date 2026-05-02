import datetime
import random
from hash_utils import generate_hash

# Map each event to a severity level
SEVERITY_MAP = {
    "User login":                  "INFO",
    "File uploaded":               "INFO",
    "File deleted":                "WARNING",
    "Permission changed":          "WARNING",
    "Auto Event":                  "INFO",
    "Unauthorized access attempt": "CRITICAL",
    "Config modified":             "CRITICAL",
    "Service restarted":           "WARNING",
}

# Mock cloud services and IPs — simulates real cloud activity sources
SOURCES = [
    ("10.0.1.12",  "auth-service"),
    ("10.0.1.34",  "file-service"),
    ("10.0.2.5",   "admin-portal"),
    ("10.0.3.18",  "api-gateway"),
    ("10.0.4.7",   "storage-service"),
    ("192.168.1.4","edge-node-01"),
    ("192.168.1.9","edge-node-02"),
]

def get_severity(event):
    return SEVERITY_MAP.get(event, "INFO")

def get_source(event):
    """
    Map events to realistic source services.
    Auth events come from auth-service, file events from file-service, etc.
    Everything else picks a random source.
    """
    if "login" in event.lower() or "access" in event.lower():
        return "10.0.1.12 / auth-service"
    elif "file" in event.lower() or "upload" in event.lower():
        return "10.0.1.34 / file-service"
    elif "permission" in event.lower() or "config" in event.lower():
        return "10.0.2.5 / admin-portal"
    elif "service" in event.lower():
        return "10.0.3.18 / api-gateway"
    else:
        ip, service = random.choice(SOURCES)
        return f"{ip} / {service}"

def create_log(event, prev_hash):
    timestamp = str(datetime.datetime.now())
    source    = get_source(event)
    data      = timestamp + event + prev_hash
    current_hash = generate_hash(data)   # HMAC-SHA256

    return {
        "timestamp":     timestamp,
        "event":         event,
        "severity":      get_severity(event),
        "source":        source,
        "previous_hash": prev_hash,
        "current_hash":  current_hash
    }