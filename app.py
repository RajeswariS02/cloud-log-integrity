from flask import Flask, render_template, redirect, url_for, jsonify
from database import (
    insert_log, get_logs, clear_logs, collection,
    insert_verification_record, get_verification_history, clear_verification_history
)
from log_generator import create_log
from verifier import verify_logs_with_index
import random

app = Flask(__name__)

@app.route("/")
def index():
    logs = get_logs()
    tampered_index = verify_logs_with_index(logs)

    # Record every verification run to history
    insert_verification_record(tampered_index)

    stats = {
        "total_logs": len(logs),
        "last_event": logs[-1]["event"] if logs else "None"
    }
    return render_template("index.html", logs=logs, tampered_index=tampered_index, stats=stats)

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
@app.route("/export/json")
def export_json():
    logs = get_logs()
    for log in logs:
        log.pop("_id", None)  # remove MongoDB internal ID
    return jsonify(logs)

@app.route("/export/csv")
def export_csv():
    import csv
    import io
    from flask import Response

    logs = get_logs()
    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow(["#", "Timestamp", "Event", "Previous Hash", "Current Hash"])

    for i, log in enumerate(logs):
        writer.writerow([
            i + 1,
            log.get("timestamp", ""),
            log.get("event", ""),
            log.get("previous_hash", ""),
            log.get("current_hash", "")
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=cloud_logs.csv"}
    )

if __name__ == "__main__":
    app.run(debug=True)