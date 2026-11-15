"""Conexión a PostgreSQL y esquema. Configuración: DATABASE_URL=postgresql://usuario:clave@host:5432/base

Sin pool de conexiones a propósito: la carga de la Fase A es baja y así no hay conexiones
colgadas entre reinicios. Si crece, cambiar a psycopg_pool sin tocar el resto del código."""
import os

import psycopg
from psycopg.rows import dict_row

DATABASE_URL = os.getenv("DATABASE_URL", "")

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS users(
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        pw_hash TEXT NOT NULL,
        verified BOOLEAN NOT NULL DEFAULT FALSE,
        verify_hash TEXT,
        reset_hash TEXT,
        reset_expires TIMESTAMPTZ,
        created TIMESTAMPTZ NOT NULL DEFAULT now())""",
    """CREATE TABLE IF NOT EXISTS sessions(
        token_hash TEXT PRIMARY KEY,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at TIMESTAMPTZ NOT NULL)""",
    "CREATE TABLE IF NOT EXISTS login_failures(id BIGSERIAL PRIMARY KEY, ip TEXT, email TEXT, "
    "at TIMESTAMPTZ NOT NULL DEFAULT now())",
    "CREATE TABLE IF NOT EXISTS signups(id BIGSERIAL PRIMARY KEY, ip TEXT, at TIMESTAMPTZ NOT NULL DEFAULT now())",
    "CREATE TABLE IF NOT EXISTS rep_usage(user_id INT NOT NULL, day DATE NOT NULL, n INT NOT NULL DEFAULT 0, "
    "PRIMARY KEY(user_id, day))",
    "CREATE TABLE IF NOT EXISTS rep_cache(url_hash TEXT PRIMARY KEY, result JSONB NOT NULL, "
    "at TIMESTAMPTZ NOT NULL DEFAULT now())",
    # user_id sin clave foránea: el administrador por API_KEY usa el id 0 (no es una fila de users).
    "CREATE TABLE IF NOT EXISTS rep_history(id BIGSERIAL PRIMARY KEY, user_id INT NOT NULL, url TEXT NOT NULL, "
    "verdict TEXT NOT NULL, at TIMESTAMPTZ NOT NULL DEFAULT now())",
    "CREATE INDEX IF NOT EXISTS rep_history_user ON rep_history(user_id, at DESC)",
    "CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, user_id INT NOT NULL, target TEXT, type TEXT, "
    "status TEXT, created DOUBLE PRECISION, data JSONB NOT NULL)",
    "CREATE INDEX IF NOT EXISTS scans_user ON scans(user_id, created DESC)",
]


def connect():
    if not DATABASE_URL:
        raise RuntimeError("Falta DATABASE_URL (postgresql://usuario:clave@host:5432/base)")
    return psycopg.connect(DATABASE_URL, autocommit=True, row_factory=dict_row)


def init():
    with connect() as c:
        for stmt in SCHEMA:
            c.execute(stmt)
