"""Escaneos persistidos en PostgreSQL (JSON completo), SIEMPRE ligados a un usuario.
Un usuario solo puede leer sus propios escaneos (get y list filtran por user_id)."""
import json
import os
import time

from . import db

MAX_SCANS = int(os.getenv("MAX_SCANS_PER_USER", "200"))


def init():
    db.init()


def save(job):
    uid = int(job.get("user_id", 0))
    with db.connect() as c:
        c.execute("""INSERT INTO scans(id,user_id,target,type,status,created,data)
                     VALUES(%s,%s,%s,%s,%s,%s,%s)
                     ON CONFLICT(id) DO UPDATE SET status=EXCLUDED.status, data=EXCLUDED.data""",
                  (job["id"], uid, job.get("target"), job.get("type"), job.get("status"),
                   float(job.get("created", time.time())), json.dumps(job, default=str)))
        c.execute("""DELETE FROM scans WHERE user_id=%s AND id NOT IN
                     (SELECT id FROM scans WHERE user_id=%s ORDER BY created DESC LIMIT %s)""",
                  (uid, uid, MAX_SCANS))


def get(jid, user_id):
    with db.connect() as c:
        row = c.execute("SELECT data FROM scans WHERE id=%s AND user_id=%s", (jid, int(user_id))).fetchone()
    return row["data"] if row else None


def list_summaries(user_id, limit=500):
    with db.connect() as c:
        rows = c.execute("SELECT id,target,type,status,created FROM scans WHERE user_id=%s "
                         "ORDER BY created DESC LIMIT %s", (int(user_id), limit)).fetchall()
    return [dict(r) for r in rows]
