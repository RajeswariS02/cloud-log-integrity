import datetime
from hash_utils import generate_hash

def create_log(event, prev_hash):
    timestamp = str(datetime.datetime.now())
    data = timestamp + event + prev_hash
    current_hash = generate_hash(data)

    return {
        "timestamp": timestamp,
        "event": event,
        "previous_hash": prev_hash,
        "current_hash": current_hash
    }