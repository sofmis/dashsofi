# vulnerscan

Orquestador (FastAPI) + plugins Docker (red, web, código/contenedores, checks personalizados) + normalización/deduplicación
+ enriquecimiento (NVD, CISA KEV, EPSS) + priorización.

## Arranque rápido (cualquier sistema con Docker)
- **macOS / Linux:** `./start.sh`   (parar: `./stop.sh`)
- **Windows:** doble clic en `start.bat`   (parar: `stop.bat`)
Requisito único: Docker Desktop abierto (macOS/Windows) o Docker Engine + Compose (Linux). Necesita ~10 GB libres.
Si falla con `input/output error`: liberar disco, `docker builder prune -f` y subir el límite de disco en Docker Desktop.

## Arranque manual
    cp .env.example .env     # define API_KEY y ALLOWED_TARGETS (falla cerrado: vacío = no se escanea nada)
    docker compose up --build
    # UI: http://127.0.0.1:8000
    # Proxy interceptor (opcional): docker compose --profile proxy up proxy  → http://127.0.0.1:8081

## Objetivos
IP/CIDR (≤ MAX_HOSTS), dominio, URL, repo git (https o /workspace/<dir>), `image:<ref>` (Trivy, por capa),
`ssh:<host>` / `winrm:<host>` (auditoría de SO autenticada, ver abajo).

## Auditoría de SO autenticada (SSH/WinRM)
Módulo `osaudit`: se conecta por SSH (Linux) o WinRM (Windows) con credenciales **solo de lectura**, recoge el
inventario de paquetes y lo coteja con **OSV.dev** usando el ecosistema de la distribución (Ubuntu, Debian, Alpine,
Rocky, Alma; RHEL/CentOS/SUSE *best-effort*). Como la versión corregida de OSV ya contempla los backports del
distribuidor, estos hallazgos son **confirmados** (no "potencial por versión"), con CVE/CVSS listos para KEV/EPSS.
- Objetivo: `ssh:[usuario@]host[:puerto]` o `winrm:[usuario@]host[:puerto]`. El host debe estar en `ALLOWED_TARGETS`.
- Credenciales por `options` (nunca se registran): `username`, `password`, `key` (clave privada SSH), `key_passphrase`,
  `known_host_key` (fijación opcional de la clave de host), `use_ssl`/`transport` (WinRM). También desde la UI.
- Comandos ejecutados: solo lectura (`os-release`, `dpkg-query`/`rpm -qa`/DB de apk; en Windows `Get-CimInstance`,
  `Get-HotFix`, claves de desinstalación). Sin sudo ni escritura.
- Windows (básico): detección de build EOL + antigüedad de actualizaciones + inventario. El cotejo de software de
  terceros por CVE (MSRC/NVD) queda para la siguiente iteración.
- `NVD_API_KEY` no es necesaria para este módulo (OSV no tiene límite estricto), pero sí conviene para el resto.

## Checks personalizados (alternativa segura a NASL)
YAML en `./checks` o desde la UI (`POST /api/checks`). Solo GET/HEAD/OPTIONS o TCP + matchers. Ver `checks/`.

## Límites conocidos
- Jobs en memoria; producción: PostgreSQL + cola (Celery/Arq) + RBAC por usuario.
- Los CVE por versión (NVD/CPE) quedan como "potencial" (confianza 0.55) por backports de las distribuciones; los hallazgos
  verificados activamente (checks, fuzzing) o corroborados por varios plugins suben a "confirmado". Así se reducen falsos positivos.
- Auditoría de SO autenticada: implementada vía OSV.dev (módulo `osaudit`). Pendiente: evaluación OVAL/USN/DSA offline
  (sin dependencia de OSV) y cotejo por CVE del software de terceros en Windows (MSRC).
- NVD sin API key tiene límite estricto (5 req/30 s): define NVD_API_KEY.
