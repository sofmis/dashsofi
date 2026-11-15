"""Correo transaccional (verificación de cuenta y recuperación de contraseña).

- Con SMTP_HOST configurado envía por SMTP (STARTTLS). Variables: SMTP_HOST, SMTP_PORT (587),
  SMTP_USER, SMTP_PASSWORD, SMTP_FROM.
- Sin SMTP, en producción se NEGARÁ a enviar: nunca se escriben enlaces de confirmación en los logs.
  Solo con MAIL_DEV=1 (desarrollo y pruebas) el enlace se muestra en el log de la consola.
"""
import logging
import os
import smtplib
from collections import deque
from email.message import EmailMessage

log = logging.getLogger("vulnerscan.mail")
RECENT = deque(maxlen=20)   # últimos correos (solo para pruebas y diagnóstico; sin datos sensibles fuera de memoria)


def send(to, subject, body):
    RECENT.append({"to": to, "subject": subject, "body": body})
    host = os.getenv("SMTP_HOST", "")
    if not host:
        if os.getenv("MAIL_DEV") == "1":
            log.warning("[MAIL_DEV] para %s: %s", to, body)
            return
        raise RuntimeError("Correo no configurado: define SMTP_HOST (y SMTP_USER / SMTP_PASSWORD)")
    msg = EmailMessage()
    msg["From"] = os.getenv("SMTP_FROM", "VulnerScan <no-reply@localhost>")
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=15) as s:
        s.starttls()
        if os.getenv("SMTP_USER"):
            s.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD", ""))
        s.send_message(msg)
