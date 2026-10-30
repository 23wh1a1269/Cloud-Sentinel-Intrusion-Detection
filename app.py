from flask import Flask, render_template, request, redirect, url_for, flash
from datetime import datetime, timezone
from pathlib import Path
import csv, io, json, re

app = Flask(__name__)
app.secret_key = "change-this-demo-secret"
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)
LOG_FILE = DATA_DIR / "security_events.jsonl"

SUSPICIOUS_PATTERNS = [
    (re.compile(r"\b(SELECT.+FROM|UNION\s+SELECT)\b", re.I), "Possible SQL injection"),
    (re.compile(r"\.\./"), "Path traversal pattern"),
    (re.compile(r"\b(nmap|sqlmap|nikto|masscan)\b", re.I), "Known scanning tool string"),
    (re.compile(r"\b(401|403)\b"), "Authentication/authorization failure"),
]

def analyze_event(event):
    text = " ".join(str(event.get(k, "")) for k in ("message", "path", "user_agent", "status"))
    reasons = [label for pattern, label in SUSPICIOUS_PATTERNS if pattern.search(text)]
    try:
        status = int(event.get("status", 0))
        if status in (401, 403):
            if "Authentication/authorization failure" not in reasons:
                reasons.append("Authentication/authorization failure")
    except (TypeError, ValueError):
        pass
    return {"severity": "HIGH" if len(reasons) >= 2 else ("MEDIUM" if reasons else "LOW"),
            "reasons": reasons}

def load_events():
    events = []
    if LOG_FILE.exists():
        for line in LOG_FILE.read_text(encoding="utf-8").splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return list(reversed(events[-300:]))

def save_event(event):
    event["received_at"] = datetime.now(timezone.utc).isoformat()
    event.update(analyze_event(event))
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

@app.route("/")
def dashboard():
    events = load_events()
    counts = {s: sum(1 for e in events if e.get("severity") == s) for s in ("HIGH", "MEDIUM", "LOW")}
    return render_template("index.html", events=events, counts=counts)

@app.route("/ingest", methods=["GET", "POST"])
def ingest():
    if request.method == "POST":
        event = {
            "source_ip": request.form.get("source_ip", "unknown")[:64],
            "path": request.form.get("path", "")[:300],
            "status": request.form.get("status", "0")[:10],
            "message": request.form.get("message", "")[:500],
            "user_agent": request.form.get("user_agent", "")[:300],
        }
        save_event(event)
        flash("Security event received and analyzed.", "success")
        return redirect(url_for("dashboard"))
    return render_template("ingest.html")

@app.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename.lower().endswith(".csv"):
        flash("Please upload a CSV file.", "error")
        return redirect(url_for("dashboard"))
    try:
        stream = io.StringIO(uploaded.stream.read().decode("utf-8-sig"))
        reader = csv.DictReader(stream)
        required = {"source_ip", "path", "status", "message", "user_agent"}
        if not required.issubset(set(reader.fieldnames or [])):
            raise ValueError("CSV must contain: " + ", ".join(sorted(required)))
        count = 0
        for row in reader:
            save_event({k: row.get(k, "") for k in required})
            count += 1
        flash(f"Imported and analyzed {count} events.", "success")
    except Exception as exc:
        flash(f"Could not import CSV: {exc}", "error")
    return redirect(url_for("dashboard"))

@app.route("/sample-data")
def sample_data():
    samples = [
        {"source_ip":"203.0.113.10","path":"/login","status":"401","message":"Repeated failed login attempt","user_agent":"Mozilla/5.0"},
        {"source_ip":"198.51.100.22","path":"/products?id=1 UNION SELECT password FROM users","status":"400","message":"Suspicious query string","user_agent":"curl/8.0"},
        {"source_ip":"192.0.2.44","path":"/../../etc/passwd","status":"403","message":"Blocked request","user_agent":"scanner"},
        {"source_ip":"192.0.2.88","path":"/home","status":"200","message":"Normal page request","user_agent":"Mozilla/5.0"},
    ]
    for item in samples:
        save_event(item)
    flash("Added four demonstration events.", "success")
    return redirect(url_for("dashboard"))

@app.route("/clear", methods=["POST"])
def clear():
    LOG_FILE.write_text("", encoding="utf-8")
    flash("Local demo event history cleared.", "success")
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
