from flask import Flask, render_template, redirect, url_for, jsonify
from database import insert_log, get_logs, clear_logs, collection
from log_generator import create_log
from verifier import verify_logs_with_index
import random

app = Flask(__name__)

@app.route("/")
def index():
    logs = get_logs()
    tampered_index = verify_logs_with_index(logs)
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
    return redirect(url_for("index"))

@app.route("/status")
def status():
    logs = get_logs()
    tampered_index = verify_logs_with_index(logs)

    if tampered_index == -1:
        return jsonify({"status": "secure"})
    else:
        return jsonify({"status": "tampered"})
        
if __name__ == "__main__":
    app.run(debug=True)