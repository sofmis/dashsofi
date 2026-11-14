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
- Windows: detección de build EOL + antigüedad de actualizaciones + inventario, **cotejo CVE del software
  reconocido** (Chrome, Firefox, 7-Zip, OpenSSL, etc.) generando un CPE que el orquestador expande a CVE vía NVD
  (mapa conservador en `winmatch.py`), **y parches del SO vía MSRC** (`msrc.py`, CVRF v3.0 oficial): compara los
  boletines mensuales posteriores al último hotfix del host para detectar actualizaciones de seguridad faltantes
  (heurística por fecha; se desactiva con `options.msrc=false` y cae a CPE/NVD si MSRC no está disponible).
- `NVD_API_KEY` no es necesaria para el cotejo OSV (Linux), pero sí acelera el cotejo CPE→CVE de Windows y del resto.

## Persistencia e interfaz
- Los escaneos se guardan en **SQLite** (`./data/vulnerscan.db`, volumen) y sobreviven a reinicios; `MAX_SCANS`
  limita el historial (500 por defecto). Para gran escala: PostgreSQL + cola.
- La interfaz incluye resumen con anillo de riesgo y barra de severidad, **barra de progreso en vivo** durante el
  escaneo, filtros/búsqueda, **comparación entre dos escaneos** (nuevas/resueltas), detalle expandible, historial,
  **visor de inventario** (paquetes/software del escaneo autenticado) e **informe descargable** (HTML imprimible a PDF).

## ¿Es maligna esta URL? (reputación, análisis pasivo)
- Acepta **cualquier URL** (con o sin `https://`). El sitio **no se visita**: solo se consultan reputaciones.
- Fuentes: **VirusTotal** (solo informes ya existentes; nunca se envía la URL para analizar, porque eso haría
  que VirusTotal visite el sitio) y **Google Safe Browsing**. Además, señales de la propia URL (IP como host,
  punycode, `@`, subdominios, extensiones de alto abuso).
- Requiere `VT_API_KEY` y `GSB_API_KEY` en `.env`. Sin claves, la fuente aparece como "sin clave"; nunca se
  inventa un veredicto. Endpoint: `GET /api/reputation?url=…` (con la API key).
- Veredicto: **maligna** (Safe Browsing o 3+ motores), **sospechosa** (1–2 motores o varias señales),
  **sin detecciones** o **sin datos**. "Sin detecciones" no garantiza que el sitio sea seguro.
- Pruebas: `python tests/test_reputation.py` (incluye la comprobación de que el sitio analizado no recibe visitas).

## Aplicaciones web modernas (SPA: React, Angular, APIs)
- Chromium ejecuta el JavaScript de la página como un usuario y **recorre las rutas del mismo origen**
  (`max_routes`, por defecto 30), descubriendo enlaces generados por el JS, título y estado por ruta.
- Endpoints `GET` que la página llama (XHR/fetch) se comprueban: si devuelven datos JSON sin autenticación se
  reporta "Endpoint de API accesible sin autenticación" (severidad baja, para revisión humana).
- Reglas: **solo GET y mismo origen**. Cualquier POST/PUT/DELETE o petición a terceros se bloquea y se registra
  por host (nunca se envían formularios ni se pulsan botones).
- Limitación: rutas que solo aparecen tras pulsar botones o con `history.pushState` sin enlace no se descubren.
- Prueba: `CHROMIUM_PATH=… python tests/test_web_render.py` (usa una SPA local de prueba).

## Código e imágenes (SAST, secretos, dependencias, capas)
- `image:<ref>`: Trivy analiza la imagen **capa por capa**. Cada vulnerabilidad indica en qué capa aparece
  (`capa 2/3`) y la instrucción del Dockerfile que la creó (p. ej. `RUN apt-get install …`).
- Repos (`https://…` o `/workspace/<dir>`): Semgrep (SAST con AST), detect-secrets (secretos, sin guardar el valor)
  y Trivy sobre lockfiles/requirements (dependencias obsoletas **antes de compilar**) y Dockerfiles.
- Si una herramienta falla, falta o devuelve una salida ilegible, el escaneo lo reporta como **error**;
  nunca devuelve "sin hallazgos" en silencio. Las pruebas: `python tests/test_code_plugin.py`.

## Fuzzing y proxy de interceptación (solo objetivos autorizados)
- **Fuzzing de detección** (`plugins/web/fuzz.py`): prueba parámetros de las páginas y formularios GET.
  Prioriza por nombre (id, file, q, url…), confirma cada hallazgo con una segunda sonda y deja de probar un
  parámetro solo en su propia clase. Detecta: XSS reflejado, SQLi por error, SQLi ciega (booleana con condiciones
  de solo lectura), traversal (con control de archivo inexistente), plantillas, open redirect y 500 reproducible.
  Los POST solo con `fuzz_post=true`. Prueba: `python tests/test_fuzz.py` (app vulnerable y app segura de prueba).
- **Proxy** (`plugins/proxy`, opcional con `--profile proxy`): mitmweb permite pausar y editar peticiones a mano.
  `rules.json` aplica reglas: cambiar o quitar cabeceras, cambiar parámetros, reemplazar cuerpo o **bloquear**
  el tráfico (403). Una regla solo actúa sobre hosts de `ALLOWED_TARGETS`; las que apuntan a otro host, o con
  claves desconocidas, se descartan y se anota el motivo.
  Pruebas: `python tests/test_proxy_rules.py` y `python tests/test_proxy_addon.py` (con mitmproxy).

## Checks personalizados (alternativa segura a NASL)
YAML en `./checks` o desde la UI (`POST /api/checks`). Solo GET/HEAD/OPTIONS o TCP + matchers. Ver `checks/`.

## Límites conocidos
- Escaneos persistidos en SQLite (ver arriba); para producción a escala: PostgreSQL + cola (Celery/Arq) + RBAC por usuario.
- Los CVE por versión (NVD/CPE) quedan como "potencial" (confianza 0.55) por backports de las distribuciones; los hallazgos
  verificados activamente (checks, fuzzing) o corroborados por varios plugins suben a "confirmado". Así se reducen falsos positivos.
- Auditoría de SO autenticada: implementada vía OSV.dev (módulo `osaudit`); Windows cotejado por CPE/NVD. Pendiente:
  evaluación OVAL/USN/DSA offline (sin dependencia de OSV) y fuente MSRC nativa para Windows (más precisa que CPE).
- NVD sin API key tiene límite estricto (5 req/30 s): define NVD_API_KEY.
