from hash_utils import generate_hash

def verify_logs_with_index(logs):
    """
    Returns a dict with:
      - tampered_index: int (-1 if clean)
      - changed_field: which field appears modified ("event" | "previous_hash" | "unknown")
      - expected_hash: what the hash should have been
      - stored_hash:   what is actually stored
    """
    prev_hash = "0"

    for i, log in enumerate(logs):
        data = log["timestamp"] + log["event"] + prev_hash
        recalculated = generate_hash(data)

        if recalculated != log["current_hash"]:
            # Try to figure out which field was tampered
            if log.get("previous_hash") != prev_hash:
                changed_field = "previous_hash"
            else:
                # timestamp rarely changes, so event is the likely culprit
                changed_field = "event"

            return {
                "tampered_index": i,
                "changed_field": changed_field,
                "expected_hash": recalculated,
                "stored_hash": log["current_hash"]
            }

        prev_hash = log["current_hash"]

    return {"tampered_index": -1, "changed_field": None,
            "expected_hash": None, "stored_hash": None}