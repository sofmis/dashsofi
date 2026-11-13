"""Persistencia de escaneos en SQLite (sobreviven a reinicios).

Los jobs eran solo en memoria. Aquí se guardan en disco sin cambiar su formato
(JSON completo), de modo que el historial, la comparación y los informes siguen
disponibles tras reiniciar el contenedor.
"""
import json
import os
import sqlite3
import threading
import time

DB_PATH = os.getenv("DB_PATH", "/data/vulnerscan.db")
MAX_SCANS = int(os.getenv("MAX_SCANS", "500"))
_lock = threading.Lock()
_ready = False


def _conn():
    d = os.path.dirname(DB_PATH)
    if d:
        os.makedirs(d, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init():
    global _ready
    with _lock:
        c = _conn()
        c.execute("""CREATE TABLE IF NOT EXISTS scans(
            id TEXT PRIMARY KEY, target TEXT, type TEXT, status TEXT,
            created REAL, data TEXT)""")
        c.commit()
        c.close()
        _ready = True


def _ensure():
    if not _ready:
        init()


def save(job):
    """Upsert del job completo; conserva solo los MAX_SCANS más recientes."""
    _ensure()
    with _lock:
        c = _conn()
        try:
            c.execute(
                "INSERT INTO scans(id,target,type,status,created,data) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET status=excluded.status, data=excluded.data",
                (job["id"], job.get("target"), job.get("type"), job.get("status"),
                 float(job.get("created", time.time())), json.dumps(job)))
            c.execute("DELETE FROM scans WHERE id NOT IN "
                      "(SELECT id FROM scans ORDER BY created DESC LIMIT ?)", (MAX_SCANS,))
            c.commit()
        finally:
            c.close()


def get(jid):
    _ensure()
    with _lock:
        c = _conn()
        try:
            row = c.execute("SELECT data FROM scans WHERE id=?", (jid,)).fetchone()
        finally:
            c.close()
    return json.loads(row[0]) if row else None


def list_summaries(limit=500):
    _ensure()
    with _lock:
        c = _conn()
        try:
            rows = c.execute(
                "SELECT id,target,type,status,created FROM scans ORDER BY created DESC LIMIT ?",
                (limit,)).fetchall()
        finally:
            c.close()
    return [{"id": a, "target": b, "type": t, "status": s, "created": cr}
            for (a, b, t, s, cr) in rows]
