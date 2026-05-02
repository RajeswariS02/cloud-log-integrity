from hash_utils import generate_hash

def verify_logs_with_index(logs):
    """
    Walks the hash chain and returns the first broken link.

    Returns a dict with:
      - tampered_index : int  (-1 if chain is clean)
      - changed_field  : str  which field was likely modified
                              ("event" | "previous_hash" | None)
      - expected_hash  : str  what the hash should be
      - stored_hash    : str  what is actually stored in the DB
    """
    prev_hash = "0"

    for i, log in enumerate(logs):
        data = log["timestamp"] + log["event"] + prev_hash
        recalculated = generate_hash(data)   # uses same HMAC-SHA256 key

        if recalculated != log["current_hash"]:
            # Heuristic: figure out which field was tampered
            if log.get("previous_hash") != prev_hash:
                changed_field = "previous_hash"
            else:
                changed_field = "event"

            return {
                "tampered_index": i,
                "changed_field":  changed_field,
                "expected_hash":  recalculated,
                "stored_hash":    log["current_hash"]
            }

        prev_hash = log["current_hash"]

    return {
        "tampered_index": -1,
        "changed_field":  None,
        "expected_hash":  None,
        "stored_hash":    None
    }
