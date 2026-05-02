from hash_utils import generate_hash

def verify_logs_with_index(logs):
    prev_hash = "0"

    for i, log in enumerate(logs):
        data = log["timestamp"] + log["event"] + prev_hash
        recalculated = generate_hash(data)

        if recalculated != log["current_hash"]:
            return i  # tampered index

        prev_hash = log["current_hash"]

    return -1