import psutil
import time
import sqlite3
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_FILE = os.path.join(BASE_DIR, "storage", "metrics.db")


class PerformanceMonitor:
    def __init__(self):
        self.prev_packets = psutil.net_io_counters().packets_recv
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS system_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            cpu REAL,
            memory REAL,
            packet_rate REAL
        )
        """)

        conn.commit()
        conn.close()

    def collect(self):
        """Collect one snapshot of system health."""
        cpu = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory().percent

        current_packets = psutil.net_io_counters().packets_recv
        packet_rate = current_packets - self.prev_packets
        self.prev_packets = current_packets

        self._store(cpu, memory, packet_rate)

    def _store(self, cpu, memory, rate):
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()

        cur.execute("""
        INSERT INTO system_metrics (timestamp, cpu, memory, packet_rate)
        VALUES (?, ?, ?, ?)
        """, (datetime.now().strftime("%H:%M:%S"), cpu, memory, rate))

        conn.commit()
        conn.close()
