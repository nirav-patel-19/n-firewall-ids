from flask import Flask, render_template, jsonify
import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_FILE = os.path.join(BASE_DIR, "storage", "events.db")

app = Flask(__name__)


def query_db(query):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def get_events():
    data = query_db("""
        SELECT readable_time, src_ip, dst_ip, proto,
               final_action, severity, reason
        FROM security_events
        ORDER BY id DESC
        LIMIT 50
    """)
    return jsonify(data)


@app.route("/api/stats")
def stats():
    data = query_db("""
        SELECT final_action, COUNT(*) as count
        FROM security_events
        GROUP BY final_action
    """)
    return jsonify(data)


@app.route("/api/blocked")
def blocked():
    data = query_db("""
        SELECT src_ip, COUNT(*) as hits
        FROM security_events
        WHERE final_action='BLOCK_IP'
        GROUP BY src_ip
    """)
    return jsonify(data)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
