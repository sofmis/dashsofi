#!/usr/bin/env bash
# Arranque en un paso (macOS / Linux): crea .env con API key aleatoria y levanta todo.
set -e
cd "$(dirname "$0")"
command -v docker >/dev/null || { echo "Instala Docker Desktop: https://www.docker.com/products/docker-desktop"; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker no está corriendo. Ábrelo, espera a que diga 'running' y reintenta."; exit 1; }
if [ ! -f .env ]; then
  cp .env.example .env
  KEY=$(openssl rand -hex 24)
  sed -i.bak "s/^API_KEY=.*/API_KEY=$KEY/" .env && rm -f .env.bak
  echo "API key generada (guárdala, la pide la interfaz): $KEY"
fi
mkdir -p checks workspace proxy-logs
docker compose up --build -d
echo "Listo -> http://127.0.0.1:8000   (logs: docker compose logs -f | parar: ./stop.sh)"
(open http://127.0.0.1:8000 || xdg-open http://127.0.0.1:8000) >/dev/null 2>&1 || true
