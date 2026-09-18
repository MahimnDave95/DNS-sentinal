from __future__ import annotations

import csv
import io
import json
import os
import re
import socket
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dnslib import DNSRecord, QTYPE, RCODE
from flask import Flask, jsonify, redirect, render_template, request, send_file

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
DB = DATA / "dns_sentinel.db"
POLICY = DATA / "policy.json"
FEED = DATA / "threat_feed.txt"
DNS_HOST = os.getenv("DNS_LISTEN_HOST", "0.0.0.0")
DNS_PORT = int(os.getenv("DNS_PORT", "53"))
WEB_HOST = os.getenv("WEB_HOST", "127.0.0.1")
WEB_PORT = int(os.getenv("WEB_PORT", "8080"))
UPSTREAM = os.getenv("UPSTREAM_DNS", "1.1.1.1")

app = Flask(__name__, template_folder="templates")
lock = threading.RLock()

DEFAULT_POLICY: dict[str, Any] = {
    "strict_ot_mode": False,
    "blocked_categories": {
        "social_media": True,
        "gambling": True,
        "streaming": False,
        "adult": True,
        "malware": True,
        "phishing": True,
        "new_domains": False,
    },
    "allowlist": ["localhost", "local", "plc.local", "scada.local", "utility.local"],
    "blocklist": [],
    "category_domains": {
        "social_media": ["facebook.com", "instagram.com", "twitter.com", "x.com", "tiktok.com", "snapchat.com", "reddit.com", "linkedin.com"],
        "gambling": ["bet365.com", "betway.com", "stake.com", "888.com"],
        "streaming": ["youtube.com", "netflix.com", "twitch.tv"],
        "adult": [],
        "malware": ["example-malware.test", "c2-beacon.test"],
        "phishing": ["login-verify.test", "secure-account.test"],
    },
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def setup() -> None:
    DATA.mkdir(exist_ok=True)
    if not POLICY.exists():
        POLICY.write_text(json.dumps(DEFAULT_POLICY, indent=2), encoding="utf-8")
    if not FEED.exists():
        FEED.write_text("c2-beacon.test\nexample-malware.test\n", encoding="utf-8")
    with sqlite3.connect(DB) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS dns_events(
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, client_ip TEXT,
        domain TEXT, qtype TEXT, category TEXT, decision TEXT, reason TEXT, risk INTEGER)""")
        db.commit()


def policy() -> dict[str, Any]:
    with lock:
        try:
            return json.loads(POLICY.read_text(encoding="utf-8"))
        except Exception:
            save_policy(DEFAULT_POLICY)
            return json.loads(json.dumps(DEFAULT_POLICY))


def save_policy(value: dict[str, Any]) -> None:
    with lock:
        POLICY.write_text(json.dumps(value, indent=2), encoding="utf-8")


def norm(value: str) -> str:
    return value.strip().lower().rstrip(".")


def matches(domain: str, rule: str) -> bool:
    domain, rule = norm(domain), norm(rule).removeprefix("*.")
    return domain == rule or domain.endswith("." + rule)


def feed_domains() -> set[str]:
    if not FEED.exists():
        return set()
    result = set()
    for line in FEED.read_text(encoding="utf-8", errors="ignore").splitlines():
        value = norm(line.split(",")[0])
        if value and "." in value and not value.startswith("#"):
            result.add(value)
    return result


def decision(domain: str) -> tuple[str, str, int]:
    p = policy()
    domain = norm(domain)
    if any(matches(domain, x) for x in p.get("allowlist", [])):
        return "allowlist", "approved by allowlist", 1
    if any(matches(domain, x) for x in feed_domains()) and p["blocked_categories"].get("malware", True):
        return "malware", "matched offline threat feed", 100
    for category, domains in p.get("category_domains", {}).items():
        if p["blocked_categories"].get(category, False) and any(matches(domain, x) for x in domains):
            return category, "matched category policy", 95
    if any(matches(domain, x) for x in p.get("blocklist", [])):
        return "custom", "matched custom blocklist", 90
    suspicious = len(domain) > 55 or bool(re.search(r"[a-z0-9]{18,}", domain)) or domain.endswith(".test")
    if p.get("strict_ot_mode") and not any(matches(domain, x) for x in p.get("allowlist", [])):
        return "unknown", "not present in strict OT allowlist", 75
    if suspicious and p["blocked_categories"].get("new_domains", False):
        return "new_domains", "anomalous domain pattern", 72
    return "uncategorised", "no blocking rule matched", 5


def add_log(client: str, domain: str, qtype: str, category: str, action: str, reason: str, risk: int) -> None:
    with sqlite3.connect(DB) as db:
        db.execute("INSERT INTO dns_events(timestamp,client_ip,domain,qtype,category,decision,reason,risk) VALUES(?,?,?,?,?,?,?,?)", (now(), client, domain, qtype, category, action, reason, risk))
        db.commit()


def events(limit: int = 500) -> list[dict[str, Any]]:
    with sqlite3.connect(DB) as db:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute("SELECT * FROM dns_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]


def forward(raw: bytes) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(raw, (UPSTREAM, 53))
        return sock.recvfrom(65535)[0]


def handle(raw: bytes, client: str) -> bytes:
    try:
        record = DNSRecord.parse(raw)
        if not record.questions:
            return raw
        question = record.questions[0]
        domain = norm(str(question.qname))
        qtype = QTYPE.get(question.qtype, str(question.qtype))
        category, reason, risk = decision(domain)
        action = "blocked" if risk >= 70 else "allowed"
        add_log(client, domain, qtype, category, action, reason, risk)
        if action == "blocked":
            reply = record.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            reply.rr, reply.auth, reply.ar = [], [], []
            return reply.pack()
        return forward(raw)
    except Exception:
        return raw


def udp_server() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((DNS_HOST, DNS_PORT))
    print(f"DNS UDP listening on {DNS_HOST}:{DNS_PORT}")
    while True:
        raw, address = sock.recvfrom(65535)
        threading.Thread(target=lambda: sock.sendto(handle(raw, address[0]), address), daemon=True).start()


def tcp_client(conn: socket.socket, address: tuple[str, int]) -> None:
    try:
        size_raw = conn.recv(2)
        if len(size_raw) != 2:
            return
        raw = conn.recv(int.from_bytes(size_raw, "big"))
        answer = handle(raw, address[0])
        conn.sendall(len(answer).to_bytes(2, "big") + answer)
    finally:
        conn.close()


def tcp_server() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((DNS_HOST, DNS_PORT))
    sock.listen(100)
    print(f"DNS TCP listening on {DNS_HOST}:{DNS_PORT}")
    while True:
        conn, address = sock.accept()
        threading.Thread(target=tcp_client, args=(conn, address), daemon=True).start()


@app.get("/")
def home():
    return redirect("/pro")


@app.get("/pro")
def dashboard():
    return render_template("professional-dns-dashboard.html")


@app.get("/api/events")
def api_events():
    return jsonify(events())


@app.delete("/api/events")
def delete_events():
    with sqlite3.connect(DB) as db:
        db.execute("DELETE FROM dns_events")
        db.commit()
    return jsonify({"ok": True, "message": "All DNS logs deleted"})


@app.get("/api/policy")
def api_policy():
    return jsonify(policy())


@app.post("/api/policy")
def api_update_policy():
    body = request.get_json(silent=True) or {}
    current = policy()
    if "strict_ot_mode" in body:
        current["strict_ot_mode"] = bool(body["strict_ot_mode"])
    if isinstance(body.get("blocked_categories"), dict):
        for key in current["blocked_categories"]:
            if key in body["blocked_categories"]:
                current["blocked_categories"][key] = bool(body["blocked_categories"][key])
    save_policy(current)
    return jsonify(current)


@app.get("/api/check")
def api_check():
    domain = norm(request.args.get("domain", ""))
    if not domain:
        return jsonify({"error": "domain is required"}), 400
    category, reason, risk = decision(domain)
    return jsonify({"domain": domain, "category": category, "reason": reason, "risk": risk, "decision": "blocked" if risk >= 70 else "allowed"})


@app.post("/api/blocklist")
def api_blocklist():
    body = request.get_json(silent=True) or {}
    domain = norm(body.get("domain", ""))
    if not domain or "." not in domain:
        return jsonify({"error": "valid domain required"}), 400
    current = policy()
    if domain not in current["blocklist"]:
        current["blocklist"].append(domain)
        save_policy(current)
    return jsonify({"ok": True, "domain": domain})


@app.post("/api/feed/import")
def api_feed_import():
    uploaded = request.files.get("file")
    if not uploaded:
        return jsonify({"error": "file is required"}), 400
    found = {norm(x) for x in re.split(r"[\s,;]+", uploaded.read().decode("utf-8", errors="ignore")) if "." in x}
    FEED.write_text("\n".join(sorted(feed_domains().union(found))) + "\n", encoding="utf-8")
    return jsonify({"ok": True, "imported": len(found)})


@app.get("/export")
def export_csv():
    output = io.StringIO()
    fields = ["timestamp", "client_ip", "domain", "qtype", "category", "decision", "reason", "risk"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(events())
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype="text/csv", as_attachment=True, download_name="dns-events.csv")


def main() -> None:
    setup()
    threading.Thread(target=udp_server, daemon=True).start()
    threading.Thread(target=tcp_server, daemon=True).start()
    print(f"Dashboard: http://{WEB_HOST}:{WEB_PORT}/pro")
    app.run(host=WEB_HOST, port=WEB_PORT, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()