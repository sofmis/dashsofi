"""Reputación: cuota diaria por usuario, caché de resultados e historial por usuario.

- La caché guarda solo el resultado público de la URL (no quién la consultó) durante 24 h,
  así que repetir la misma URL no gasta cuota de VirusTotal/Google.
- El historial es privado: cada usuario ve solo sus consultas (últimas 200)."""
import hashlib
import json
import os

from . import db
from .accounts import AuthError

REP_DAILY = int(os.getenv("REP_DAILY_LIMIT", "30"))
HISTORY_KEEP = 200


def _key(url):
    return hashlib.sha256(url.encode()).hexdigest()


def take_quota(user_id):
    """Cuenta una consulta y devuelve las que quedan hoy. Lanza AuthError(429) si se agotó."""
    with db.connect() as c:
        n = c.execute("SELECT n FROM rep_usage WHERE user_id=%s AND day=CURRENT_DATE",
                      (int(user_id),)).fetchone()
        used = n["n"] if n else 0
        if used >= REP_DAILY:
            raise AuthError(429, f"Has alcanzado el límite diario ({REP_DAILY} consultas). Vuelve mañana.")
        c.execute("INSERT INTO rep_usage(user_id,day,n) VALUES(%s,CURRENT_DATE,1) "
                  "ON CONFLICT(user_id,day) DO UPDATE SET n=rep_usage.n+1", (int(user_id),))
    return REP_DAILY - (used + 1)


def cache_get(url):
    with db.connect() as c:
        row = c.execute("SELECT result FROM rep_cache WHERE url_hash=%s AND at > now() - interval '24 hours'",
                        (_key(url),)).fetchone()
    return row["result"] if row else None


def cache_put(url, result):
    with db.connect() as c:
        c.execute("INSERT INTO rep_cache(url_hash,result,at) VALUES(%s,%s,now()) "
                  "ON CONFLICT(url_hash) DO UPDATE SET result=EXCLUDED.result, at=now()",
                  (_key(url), json.dumps(result)))


def history_add(user_id, url, verdict):
    with db.connect() as c:
        c.execute("INSERT INTO rep_history(user_id,url,verdict) VALUES(%s,%s,%s)", (int(user_id), url[:2048], verdict))
        c.execute("""DELETE FROM rep_history WHERE user_id=%s AND id NOT IN
                     (SELECT id FROM rep_history WHERE user_id=%s ORDER BY at DESC LIMIT %s)""",
                  (int(user_id), int(user_id), HISTORY_KEEP))


def history_list(user_id, limit=50):
    with db.connect() as c:
        rows = c.execute("SELECT url, verdict, at FROM rep_history WHERE user_id=%s ORDER BY at DESC LIMIT %s",
                         (int(user_id), limit)).fetchall()
    return [{"url": r["url"], "verdict": r["verdict"], "at": r["at"].isoformat()} for r in rows]
