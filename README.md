# 🔐 Tamper-Proof Cloud Log Monitoring System

A cloud security monitoring system that uses a **cryptographic HMAC hash chain** to detect log tampering in real time. Built as a course project for Secure Cloud/Edge/IoT.

---

## What It Does

Every log entry is cryptographically linked to the previous one. If any log is modified — even a single character — the chain breaks and the system immediately flags the tampered entry, identifies the suspected field, and shows the expected vs. stored hash side by side.

This mirrors how real systems like AWS CloudTrail protect audit logs.

---

## Tech Stack

| Layer      | Technology                        |
|------------|-----------------------------------|
| Backend    | Python 3, Flask                   |
| Database   | MongoDB (via PyMongo)             |
| Security   | HMAC-SHA256 (Python `hmac` module)|
| Frontend   | Bootstrap 5, vanilla JavaScript   |

---

## Features

### 🔗 Hash Chain Integrity
- Each log stores `timestamp`, `event`, `source`, `severity`, `previous_hash`, `current_hash`
- Hash is computed as `HMAC-SHA256(secret_key, timestamp + event + prev_hash)`
- Verification recomputes every hash and detects the first broken link
- One tampered log invalidates all subsequent logs in the chain

### 🔑 HMAC-SHA256 Signing
- Replaced plain SHA-256 with keyed HMAC — an attacker cannot forge a valid hash without the secret key
- Secret key loaded from `LOG_HMAC_SECRET` environment variable (falls back to a default for demo)

### 📡 Real-Time Monitoring
- JavaScript polls `/status` every 10 seconds — no page refresh needed
- Animated pulse dot: 🟢 green (secure) / 🔴 red (tampered)
- Shows exact tampered index and last checked timestamp

### 🚨 Tamper Detection Details
- Identifies tampered log index and suspected field (`event` or `previous_hash`)
- Displays expected hash vs. stored (corrupted) hash with copy-to-clipboard
- Records the first-ever detection timestamp across sessions

### 🧾 Verification History (Audit of the Audit)
- Every page load records a verification run to a separate MongoDB collection
- History table shows last 20 runs: timestamp, status, total logs, tampered index
- Green rows = secure, red rows = tampered — gives a full audit trail

### ⚠️ Severity Classification
- Events classified as `INFO` / `WARNING` / `CRITICAL`
- Color-coded rows and badges in the log table
- Filter buttons to isolate logs by severity level

### 🌐 Source Attribution
- Each log records a mock source: `IP address / service-name`
- Events are mapped to realistic services (e.g. login → `auth-service`, file ops → `file-service`)
- Makes logs look and feel like real cloud system output

### 🔧 Incident Response (Restore Chain)
- `/restore` detects the tampered index and deletes all logs from that point onward
- Restore button only appears when tampering is detected — disappears once chain is clean
- Requires confirmation before deleting — no accidental data loss

### 📤 Export
- `/export/json` — downloads full log array as a formatted JSON file
- `/export/csv` — downloads logs as CSV with all fields including source

### 💣 Attack Simulation
- `/tamper` modifies a randomly chosen log's `event` field without updating the hash
- Demonstrates mid-chain and end-chain tampering, not just index 0

---

## Project Structure

```
cloud-log-integrity/
├── app.py              # Flask routes and application logic
├── database.py         # MongoDB connection, log and history operations
├── hash_utils.py       # HMAC-SHA256 hash generation
├── log_generator.py    # Log creation with source attribution and severity
├── verifier.py         # Hash chain verification logic
├── templates/
│   └── index.html      # Dashboard UI (Bootstrap + JS polling)
├── requirements.txt
└── README.md
```

---

## How to Run

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Start MongoDB
```bash
mongod
```

### 3. (Optional) Set HMAC secret key
```bash
export LOG_HMAC_SECRET="your-secret-key-here"
```

### 4. Run the app
```bash
python app.py
```

### 5. Open in browser
```
http://127.0.0.1:5000
```

---

## Demo Flow

| Step | Action | What to observe |
|------|--------|-----------------|
| 1 | Click **Generate Log** a few times | Chain builds, status dot goes green |
| 2 | Click **Generate 50 Logs** | Bulk chain generation at scale |
| 3 | Click **Simulate Attack** | Red banner appears with tampered index, field, and hash diff |
| 4 | Watch status dot | Flips red within 10 seconds automatically |
| 5 | Use severity filter buttons | Isolate INFO / WARNING / CRITICAL rows |
| 6 | Click **Export CSV** | Downloads full log chain for forensic analysis |
| 7 | Click **Restore Chain** → confirm | Corrupted logs removed, chain goes secure |

---

## Security Design

### Why HMAC over plain SHA-256?
Plain SHA-256 is a public algorithm — an attacker who tampers with a log can just recompute a valid hash. HMAC binds the hash to a secret key. Without the key, a tampered log produces a hash that fails verification.

### Why does one tampered log break everything downstream?
Each log's hash depends on the previous log's hash. If log #3 is tampered, log #4's `previous_hash` no longer matches what was expected — and every log after it is equally untrustworthy.

### Known limitation (intentional for course scope)
A sophisticated attacker with access to the secret key could tamper with a log *and* recompute all subsequent hashes. In production, this is mitigated by storing the HMAC key in a hardware security module (HSM) separate from the log storage.

---

## API Reference

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Main dashboard |
| `/generate` | GET | Generate one random log |
| `/bulk_generate` | GET | Generate 50 logs |
| `/tamper` | GET | Simulate attack on a random log |
| `/restore` | GET | Delete logs from tampered index onward |
| `/clear` | GET | Clear all logs and verification history |
| `/status` | GET | JSON: current chain status |
| `/history` | GET | JSON: last 20 verification runs |
| `/export/json` | GET | Download logs as JSON |
| `/export/csv` | GET | Download logs as CSV |

---

## Team

Built for the Secure Cloud/Edge/IoT course.
=======
# Cloud Log Integrity Verification System

This project implements a secure cloud log monitoring system using cryptographic hash chains to detect tampering.

## Features
- Log generation and storage
- Hash chain integrity verification
- Tampering detection
- Real-time dashboard
- Attack simulation

## Tech Stack
- Python (Flask)
- MongoDB
- Bootstrap

## How to Run
1. Install dependencies
2. Start MongoDB
3. Run `python app.py`
4. Open http://127.0.0.1:5000
