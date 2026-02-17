import os
import json
import csv
import sqlite3
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LOG_DIR = os.path.join(BASE_DIR, "logs")
DB_DIR = os.path.join(BASE_DIR, "storage")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(DB_DIR, exist_ok=True)

JSON_LOG = os.path.join(LOG_DIR, "events.jsonl")
CSV_LOG = os.path.join(LOG_DIR, "events.csv")
DB_FILE = os.path.join(DB_DIR, "events.db")

class EventLogger:
    def __init__(self):
        self._init_csv()
        self._init_db()

    # ---------- JSON LOG ----------

    def log_json(self,event):
            event["readable_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(JSON_LOG, "a") as f:
                f.write(json.dumps(event) + "\n")

    # ---------- CSV LOG ----------
    def _init_csv(self):
        if not os.path.exists(CSV_LOG):
            with open(CSV_LOG, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp",
                    "readable_time",
                    "src_ip",
                    "dst_ip",
                    "proto",
                    "fw_decision",
                    "ids_alert",
                    "final_action",
                    "severity",
                    "reason"
                ])

    def log_csv(self, event):
        with open(CSV_LOG, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                event["timestamp"],
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                event["src_ip"],
                event["dst_ip"],
                event["proto"],
                event["fw_decision"],
                event["ids_alert"],
                event["final_action"],
                event["severity"],
                event["reason"]
            ])

    # ---------- SQLITE STORAGE ----------
    def _init_db(self):
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()

        cur.execute(
            """
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    readable_time TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    proto TEXT,
                    fw_decision TEXT,
                    ids_alert TEXT,
                    final_action TEXT,
                    severity TEXT,
                    reason TEXT
                )
            """
        )

        conn.commit()
        conn.close()

    def log_db(self, event):
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO security_events (
                timestamp, readable_time, src_ip, dst_ip, proto, fw_decision, ids_alert, final_action, severity, reason
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event["timestamp"],
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                event["src_ip"],
                event["dst_ip"],
                event["proto"],
                event["fw_decision"],
                event["ids_alert"],
                event["final_action"],
                event["severity"],
                event["reason"]
                )
        )

        conn.commit()
        conn.close()

    def log_event(self, event):
        self.log_json(event)
        self.log_csv(event)
        self.log_db(event)
