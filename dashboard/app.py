from flask import Flask, render_template, jsonify, request, redirect, session, make_response
import sqlite3
import sys
import os
from collections import Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

# make firewall modules importable
sys.path.insert(0, PROJECT_ROOT)

DB_FILE = os.path.join(PROJECT_ROOT, "storage", "events.db")

print(f"[Dashboard] Using DB at: {DB_FILE}")

app = Flask(__name__)
app.secret_key = "firewall-secret-key"


# ---------------- DATABASE ---------------- #

def query_db(query, args=()):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=5, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(query, args)
        rows = cur.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except:
        return []


@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store"
    return response


def login_required():
    return "user" in session


# ---------------- AUTH ---------------- #

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["username"] == "nirav" and request.form["password"] == "123":
            session["user"] = "nirav"
            return redirect("/admin")
        return render_template("login.html", error="Invalid Credentials")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------------- DASHBOARD ---------------- #

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def get_events():
    return jsonify(query_db("""
        SELECT readable_time, src_ip, dst_ip, proto,
               final_action, severity, reason
        FROM security_events
        ORDER BY id DESC
        LIMIT 50
    """))


@app.route("/api/stats")
def get_stats():
    rows = query_db("SELECT proto, final_action, src_ip FROM security_events")

    proto = Counter()
    actions = Counter()
    attackers = Counter()

    for r in rows:
        proto[r["proto"]] += 1
        actions[r["final_action"]] += 1
        attackers[r["src_ip"]] += 1

    return jsonify({
        "protocols": dict(proto),
        "actions": dict(actions),
        "top_attackers": attackers.most_common(5)
    })


# ---------------- ADMIN ---------------- #

@app.route("/admin")
def admin():
    if not login_required():
        return redirect("/login")
    return render_template("admin.html")


@app.route("/api/blocked_ips")
def blocked_ips():
    if not login_required():
        return jsonify({"error": "Unauthorized"}), 403

    from rules.engine import load_rules

    rules = load_rules()

    blocked_ips = rules.get("blocked_ips", [])

    # Return format expected by admin.html
    result = [{"src_ip": ip, "hits": "ACTIVE"} for ip in blocked_ips]

    return jsonify(result)


@app.route("/api/block_ip", methods=["POST"])
def block_ip():
    if not login_required():
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    ip = data.get("ip")
    action = data.get("action", "add")

    from rules.engine import add_block_rule, remove_block_rule

    print(f"[Dashboard] {action.upper()} rule requested for {ip}")

    if action == "add":
        result = add_block_rule(ip)
    else:
        result = remove_block_rule(ip)

    print(f"[Dashboard] Rule update result: {result}")

    return jsonify({"success": result})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
