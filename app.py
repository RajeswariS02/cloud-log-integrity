from flask import Flask, render_template, redirect, url_for, jsonify
from database import (
    insert_log, get_logs, clear_logs, collection,
    insert_verification_record, get_verification_history, clear_verification_history,
    verification_collection
)
from log_generator import create_log
from verifier import verify_logs_with_index
import random

app = Flask(__name__)

@app.route("/")
def index():
    logs = get_logs()
    result = verify_logs_with_index(logs)
    tampered_index = result["tampered_index"]

    # Record this verification run
    insert_verification_record(tampered_index)

    # Find when tampering was FIRST detected (earliest record with status=tampered)
    first_tamper_record = verification_collection.find_one(
        {"status": "tampered"},
        sort=[("timestamp", 1)]
    )
    first_detected_at = first_tamper_record["timestamp"] if first_tamper_record else None

    stats = {
        "total_logs": len(logs),
        "last_event": logs[-1]["event"] if logs else "None"
    }

    return render_template(
        "index.html",
        logs=logs,
        tampered_index=tampered_index,
        changed_field=result["changed_field"],
        expected_hash=result["expected_hash"],
        stored_hash=result["stored_hash"],
        first_detected_at=first_detected_at,
        stats=stats
    )

@app.route("/generate")
def generate():
    logs = get_logs()
    prev_hash = logs[-1]["current_hash"] if logs else "0"

    event = random.choice([
        "User login",
        "File uploaded",
        "File deleted",
        "Permission changed"
    ])

    log = create_log(event, prev_hash)
    insert_log(log)
    return redirect(url_for("index"))

@app.route("/bulk_generate")
def bulk_generate():
    logs = get_logs()
    prev_hash = logs[-1]["current_hash"] if logs else "0"

    for _ in range(50):
        log = create_log("Auto Event", prev_hash)
        insert_log(log)
        prev_hash = log["current_hash"]

    return redirect(url_for("index"))

@app.route("/tamper")
def tamper():
    logs = get_logs()
    if logs:
        collection.update_one(
            {"_id": logs[0]["_id"]},
            {"$set": {"event": "HACKED DATA"}}
        )
    return redirect(url_for("index"))

@app.route("/clear")
def clear():
    clear_logs()
    clear_verification_history()
    return redirect(url_for("index"))

@app.route("/status")
def status():
    logs = get_logs()
    tampered_index = verify_logs_with_index(logs)

    if tampered_index == -1:
        return jsonify({"status": "secure"})
    else:
        return jsonify({"status": "tampered", "tampered_index": tampered_index})

@app.route("/history")
def history():
    records = get_verification_history()
    # Remove MongoDB _id (not JSON serializable)
    for r in records:
        r.pop("_id", None)
    return jsonify(records)
@app.route("/restore")
def restore():
    logs = get_logs()
    result = verify_logs_with_index(logs)
    tampered_index = result["tampered_index"]
 
    if tampered_index != -1:
        # Get timestamps of all logs from tampered index onward and delete them
        logs_to_delete = logs[tampered_index:]
        ids_to_delete = [log["_id"] for log in logs_to_delete]
        collection.delete_many({"_id": {"$in": ids_to_delete}})
 
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)