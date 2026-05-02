from flask import Flask, render_template, redirect, url_for, jsonify, Response
from database import (
    insert_log, get_logs, clear_logs, collection,
    insert_verification_record, get_verification_history, clear_verification_history,
    verification_collection
)
from log_generator import create_log
from verifier import verify_logs_with_index
import random
import csv
import io
import json

app = Flask(__name__)

@app.route("/")
def index():
    logs = get_logs()
    result = verify_logs_with_index(logs)
    tampered_index = result["tampered_index"]  # int: -1 or index

    # Record this verification run ONLY on direct page visits
    # (not on every redirect — avoids duplicate history entries)
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
        # Pick a random log index instead of always log[0]
        target_index = random.randint(0, len(logs) - 1)
        collection.update_one(
            {"_id": logs[target_index]["_id"]},
            {"$set": {"event": "HACKED DATA"}}
        )
    return redirect(url_for("index"))

@app.route("/clear")
def clear():
    clear_logs()
    clear_verification_history()
    return redirect(url_for("index"))

# ── BUG FIX: /status was assigning the dict directly to tampered_index ──────
@app.route("/status")
def status():
    logs = get_logs()
    result = verify_logs_with_index(logs)          # returns a dict
    tampered_index = result["tampered_index"]       # extract the int

    if tampered_index == -1:
        return jsonify({"status": "secure"})
    else:
        return jsonify({"status": "tampered", "tampered_index": tampered_index})

@app.route("/history")
def history():
    records = get_verification_history()
    for r in records:
        r.pop("_id", None)
    return jsonify(records)

@app.route("/restore")
def restore():
    logs = get_logs()
    result = verify_logs_with_index(logs)
    tampered_index = result["tampered_index"]

    if tampered_index != -1:
        logs_to_delete = logs[tampered_index:]
        ids_to_delete = [log["_id"] for log in logs_to_delete]
        collection.delete_many({"_id": {"$in": ids_to_delete}})

    return redirect(url_for("index"))

# ── NEW: Export routes (buttons existed in UI but routes were missing) ───────
@app.route("/export/json")
def export_json():
    logs = get_logs()
    clean_logs = []
    for log in logs:
        log.pop("_id", None)
        clean_logs.append(log)

    response = Response(
        json.dumps(clean_logs, indent=2, default=str),
        mimetype="application/json"
    )
    response.headers["Content-Disposition"] = "attachment; filename=cloud_logs.json"
    return response

@app.route("/export/csv")
def export_csv():
    logs = get_logs()
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["#", "Timestamp", "Event", "Severity", "Source", "Previous Hash", "Current Hash"])
    for i, log in enumerate(logs, start=1):
        writer.writerow([
            i,
            log.get("timestamp", ""),
            log.get("event", ""),
            log.get("severity", ""),
            log.get("source", "unknown"),
            log.get("previous_hash", ""),
            log.get("current_hash", "")
        ])

    response = Response(output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=cloud_logs.csv"
    return response

if __name__ == "__main__":
    app.run(debug=True)