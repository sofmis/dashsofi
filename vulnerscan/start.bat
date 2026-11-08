@echo off
REM Arranque en Windows (requiere Docker Desktop abierto)
cd /d %~dp0
docker info >nul 2>&1 || (echo Docker no esta corriendo. Abre Docker Desktop y reintenta. & exit /b 1)
if not exist .env (
  copy .env.example .env >nul
  echo Se creo .env. Cambia API_KEY por una clave larga, guarda y cierra el Bloc de notas.
  notepad .env
)
if not exist checks mkdir checks
if not exist workspace mkdir workspace
if not exist proxy-logs mkdir proxy-logs
docker compose up --build -d
start http://127.0.0.1:8000
