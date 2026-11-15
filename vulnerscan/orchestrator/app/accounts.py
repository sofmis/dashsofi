"""Cuentas: registro con email y contraseña, verificación, recuperación, sesiones y protección
contra fuerza bruta y registros masivos.

Diseño:
- Contraseñas con scrypt (memoria dura), sin dependencias externas.
- Tokens de un solo uso (verificación, recuperación) y sesiones: solo se guarda su SHA-256.
- Respuestas genéricas en registro y recuperación para no revelar qué correos existen.
- Un inicio de sesión con correo desconocido también gasta el tiempo de scrypt (no filtra cuentas)."""
import hashlib
import hmac
import os
import re
import secrets
from datetime import timedelta

from . import db, mailer

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
PW_MIN, PW_MAX = 10, 200
COMMON = {"1234567890", "password12", "qwertyuiop1", "contraseña12", "vulnerscan1", "administrador"}
SESSION_DAYS = int(os.getenv("SESSION_DAYS", "14"))
FAILS_PER_ACCOUNT, FAILS_PER_IP = 8, 40          # en 15 minutos
SIGNUPS_PER_IP_HOUR = 5
GENERIC_SIGNUP = "Si el correo es válido, te enviamos un enlace para confirmar la cuenta."
GENERIC_FORGOT = "Si el correo existe, te enviamos un enlace para restablecer la contraseña."


class AuthError(Exception):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status, self.msg = status, msg


def _h(t):
    return hashlib.sha256(t.encode()).hexdigest()


def hash_password(pw):
    salt = os.urandom(16)
    n, r, p = 2 ** 14, 8, 1
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${salt.hex()}${dk.hex()}"


def verify_password(pw, stored):
    try:
        _, n, r, p, salt, dk = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc, bytes.fromhex(dk))
    except (ValueError, TypeError):
        return False


_DUMMY = hash_password("hash-de-relleno-para-tiempos")


def normalize_email(e):
    e = (e or "").strip().lower()
    if len(e) > 254 or not EMAIL_RE.match(e):
        raise AuthError(400, "Correo no válido")
    return e


def check_password(pw, email):
    if not pw or len(pw) < PW_MIN:
        raise AuthError(400, f"La contraseña debe tener al menos {PW_MIN} caracteres")
    if len(pw) > PW_MAX:
        raise AuthError(400, "Contraseña demasiado larga")
    if pw.lower() in COMMON or pw.lower() == email.lower():
        raise AuthError(400, "Contraseña demasiado común")


def register(email, pw, ip, base_url):
    email = normalize_email(email)
    check_password(pw, email)
    with db.connect() as c:
        n = c.execute("SELECT count(*) AS n FROM signups WHERE ip=%s AND at > now() - interval '1 hour'",
                      (ip,)).fetchone()["n"]
        if n >= SIGNUPS_PER_IP_HOUR:
            raise AuthError(429, "Demasiados registros desde tu red. Inténtalo más tarde.")
        c.execute("INSERT INTO signups(ip) VALUES(%s)", (ip,))
        exists = c.execute("SELECT 1 FROM users WHERE email=%s", (email,)).fetchone()
    if not exists:
        tok = secrets.token_urlsafe(32)
        # Primero el correo: si no se puede enviar, NO se crea la cuenta (así puede volver a intentarlo).
        try:
            mailer.send(email, "Confirma tu cuenta de VulnerScan",
                        f"Confirma tu correo abriendo este enlace:\n{base_url}/?verify={tok}\n\n"
                        "Si no fuiste tú, ignora este mensaje.")
        except Exception:
            raise AuthError(503, "El servicio de correo no está disponible en este momento. Inténtalo más tarde.")
        with db.connect() as c:
            c.execute("INSERT INTO users(email,pw_hash,verify_hash) VALUES(%s,%s,%s) ON CONFLICT (email) DO NOTHING",
                      (email, hash_password(pw), _h(tok)))
    return GENERIC_SIGNUP


def verify_email(tok):
    with db.connect() as c:
        row = c.execute("UPDATE users SET verified=TRUE, verify_hash=NULL WHERE verify_hash=%s RETURNING id",
                        (_h(tok or ""),)).fetchone()
    if not row:
        raise AuthError(400, "Enlace no válido o ya usado")
    return True


def _throttle(c, ip, email):
    by_email = c.execute("SELECT count(*) AS n FROM login_failures WHERE email=%s "
                         "AND at > now() - interval '15 minutes'", (email,)).fetchone()["n"]
    by_ip = c.execute("SELECT count(*) AS n FROM login_failures WHERE ip=%s "
                      "AND at > now() - interval '15 minutes'", (ip,)).fetchone()["n"]
    if by_email >= FAILS_PER_ACCOUNT or by_ip >= FAILS_PER_IP:
        raise AuthError(429, "Demasiados intentos fallidos. Espera 15 minutos e inténtalo de nuevo.")


def login(email, pw, ip):
    """Devuelve (token_de_sesion, verificado). Lanza AuthError si no es válido."""
    email = (email or "").strip().lower()
    with db.connect() as c:
        _throttle(c, ip, email)
        u = c.execute("SELECT id, pw_hash, verified FROM users WHERE email=%s", (email,)).fetchone()
        ok = verify_password(pw or "", u["pw_hash"] if u else _DUMMY) and u is not None
        if not ok:
            c.execute("INSERT INTO login_failures(ip,email) VALUES(%s,%s)", (ip, email))
            raise AuthError(401, "Correo o contraseña incorrectos")
        tok = secrets.token_urlsafe(32)
        c.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(%s,%s, now() + make_interval(days => %s))",
                  (_h(tok), u["id"], SESSION_DAYS))
    return tok, u["verified"]


def user_from_session(tok):
    if not tok:
        return None
    with db.connect() as c:
        row = c.execute("SELECT u.id, u.email, u.verified FROM sessions s JOIN users u ON u.id=s.user_id "
                        "WHERE s.token_hash=%s AND s.expires_at > now()", (_h(tok),)).fetchone()
    return dict(row) if row else None


def logout(tok):
    if tok:
        with db.connect() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=%s", (_h(tok),))


def forgot(email, base_url):
    try:
        email = normalize_email(email)
    except AuthError:
        return GENERIC_FORGOT
    with db.connect() as c:
        row = c.execute("SELECT id FROM users WHERE email=%s", (email,)).fetchone()
        if row:
            tok = secrets.token_urlsafe(32)
            c.execute("UPDATE users SET reset_hash=%s, reset_expires=now() + interval '1 hour' WHERE id=%s",
                      (_h(tok), row["id"]))
            mailer.send(email, "Restablece tu contraseña de VulnerScan",
                        f"Abre este enlace para elegir una nueva contraseña (caduca en 1 hora):\n"
                        f"{base_url}/?reset={tok}\n\nSi no fuiste tú, ignora este mensaje.")
    return GENERIC_FORGOT


def reset_password(tok, pw):
    with db.connect() as c:
        row = c.execute("SELECT id, email FROM users WHERE reset_hash=%s AND reset_expires > now()",
                        (_h(tok or ""),)).fetchone()
        if not row:
            raise AuthError(400, "Enlace no válido o caducado")
        check_password(pw, row["email"])
        c.execute("UPDATE users SET pw_hash=%s, reset_hash=NULL, reset_expires=NULL WHERE id=%s",
                  (hash_password(pw), row["id"]))
        c.execute("DELETE FROM sessions WHERE user_id=%s", (row["id"],))   # cierra todas las sesiones
    return True
