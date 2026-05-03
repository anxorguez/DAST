# DAST Framework — Claude Code Memory

## Project Overview

**dast-framework** es un framework de Dynamic Application Security Testing (DAST) desarrollado como TFM. Detecta vulnerabilidades de inyección (SQLi, XSS, CMDi, SSRF, XXE, Deserialización, Path Traversal, Open Redirect) en aplicaciones web usando Playwright para crawling headless y un pipeline de escaneo modular.

- **Lenguaje:** Python 3.12 (mypy strict, ruff linting)
- **Arquitectura:** pipeline de 4 módulos → Crawler → VectorAnalyzer → Fuzzer → ReportGenerator
- **Runtime:** contenedor Docker (`dast-app`), target de pruebas es DVWA
- **Gestor de paquetes:** pip + `pyproject.toml` (setuptools)

---

## Estructura del repositorio

```
src/
  core/           # Settings (Pydantic), logger, HTTP client, excepciones
  crawler/        # Crawler BFS con Playwright + segundo pase stored XSS
  vectors/        # Modelos AttackVector + VectorAnalyzer (BeautifulSoup4)
  fuzzing/        # Fuzzer orchestrator + módulos scanner (uno por VulnType)
  analysis/       # Validator, SeverityScorer (CVSS 3.1), ReportGenerator
  pipeline.py     # Orquestador end-to-end
payloads/         # Archivos .txt de payloads por tipo de vulnerabilidad
config/           # Perfiles YAML de escaneo (default, aggressive, stealth)
templates/        # Plantilla HTML Jinja2 para el reporte
tests/
  unit/           # Tests unitarios pytest (sin dependencias externas)
  integration/    # Tests de integración pytest (requieren DVWA activo)
reports/
  outputs/        # Salidas de los escaneos (no versionadas)
    <scan_name>/
      report.json
      report.html
      findings.db
      scan.log
    debug/        # Escaneos abortados — solo el scan.log se preserva
      <failed_scan_name>/scan.log
  docs/           # Documentación del TFM y prompts (versionados)
    TFM_completo.docx   # Documentación del proyecto (DEBE mantenerse actualizada)
    TFM_plantilla.docx  # Plantilla de estilos de la documentación
    prompts/            # Prompts en markdown que originaron cambios
```

**Reglas de salida**:
- `reports/` solo contiene `outputs/` y `docs/`. Nada debe escribirse directamente bajo `reports/`.
- Cada escaneo escribe a `reports/outputs/<scan_name>/`.
- Si el proceso Python termina con exit code distinto de 0 o sin generar
  `report.json`, su `scan.log` se mueve a `reports/outputs/debug/<scan_name>/`
  y el directorio original se limpia.

---

## Reglas de trabajo obligatorias

Estas reglas son criterios de éxito. Una tarea no está terminada hasta que se cumplan todas.

### 1. Los checks de CI deben pasar siempre

El usuario hace push manualmente. Claude nunca hace push ni commit. Pero es responsabilidad de Claude que cuando el usuario haga push, las pipelines de GitHub Actions den verde.

Al terminar cualquier tarea, Claude ejecuta obligatoriamente:

```bash
# Replica exacta del workflow Lint (.github/workflows/lint.yml)
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/

# Replica exacta del workflow Test — job unit-tests (.github/workflows/test.yml)
pytest tests/unit/ -v --tb=short
```

Si algo falla: corregirlo, volver a ejecutar, y no dar la tarea por terminada hasta que los cuatro comandos pasen sin errores.

Para los **tests de integración** (requieren DVWA activo): ejecutarlos solo si el entorno está levantado. Si no está disponible, avisarlo explícitamente:
> ⚠️ Tests de integración no verificados — DVWA no está levantado. Verifica el check en GitHub Actions tras el push.

### 2. Documentación — actualizar al terminar cada tarea

Tras completar cualquier tarea:

- Abrir `reports/docs/TFM_completo.docx`
- Revisar qué secciones se ven afectadas
- Actualizar o añadir contenido usando los estilos de `TFM_plantilla.docx`
- Guardar antes de dar la tarea por terminada

### 3. Verificación activa con Docker tras cada cambio funcional

Cuando se cree o modifique una funcionalidad:

1. `docker compose up -d dvwa db && docker compose build dast-app`
2. `docker compose run --rm dast-app --url http://dvwa --concurrent-vectors 5 --concurrent-payloads 10 --requests-per-second 0 --depth 3 --max-pages 100 --max-payloads-per-vector 50 --payload-types sqli,xss,cmdi,ssrf,xxe,deserialization,path_traversal,open_redirect --request-timeout 30`
3. Revisar la salida en consola y los archivos en `reports/outputs/<scan_name>/`
4. No dar la tarea por terminada hasta que la salida sea la esperada

### 4. Registro explícito de archivos modificados

En cada respuesta donde se toquen archivos:

```
Archivos modificados:
- src/fuzzing/fuzzer.py       →  líneas 45-67 (descripción del cambio)
- src/core/config.py          →  líneas 12, 89 (descripción del cambio)
- tests/unit/test_fuzzer.py   →  líneas 110-135 (descripción del cambio)
```

Aplica a todos los archivos sin excepción.

---

## Convenciones de código

**Longitud de línea — 100 caracteres.**
Configurado en `pyproject.toml`. Líneas más largas rompen el lint.

**Type annotations — tipos en todas las funciones públicas.**
```python
# MAL
def scan(vector, payloads):

# BIEN
def scan(self, vector: AttackVector, payloads: list[str]) -> list[RawFinding]:
```
`mypy` en modo strict lo comprueba. Si falta un tipo, falla la pipeline Lint.

**`from __future__ import annotations` — primera línea de cada módulo.**
Va al principio de todos los `.py`. Permite usar sintaxis moderna de tipos sin problemas de compatibilidad.

**Logger — siempre `loguru`, nunca `logging`.**
```python
from loguru import logger
logger.info("Mensaje con {variable}", variable=valor)
```
Ya está configurado globalmente en `src/core/logger.py`.

**`verify=False` en HTTPX — es intencional.**
Los scanners necesitan funcionar contra targets con SSL autofirmado. La regla `S501` de ruff está desactivada en `pyproject.toml` por este motivo.

---

## CI/CD — pipelines de GitHub Actions

| Workflow | Archivo | Qué comprueba |
|---|---|---|
| **Lint** | `.github/workflows/lint.yml` | `ruff check`, `ruff format --check`, `mypy src/` |
| **Test** | `.github/workflows/test.yml` | Tests unitarios + integración contra DVWA |
| **Docker Build** | `.github/workflows/docker-build.yml` | Build multi-arch, push a GHCR en tag/main |

**El push lo hace el usuario manualmente. Claude nunca hace push ni commit.**

---

## Comandos habituales

```bash
# Linting y tipos
ruff check src/ tests/
ruff format src/ tests/
mypy src/

# Tests
pytest tests/unit/ -v
pytest tests/unit/ --cov=src --cov-report=term-missing

# Entorno Docker
./start.sh
docker compose build dast-app
docker compose run --rm dast-app --url http://dvwa \
    --concurrent-vectors 5 --concurrent-payloads 10 --requests-per-second 0 \
    --depth 3 --max-pages 100 --max-payloads-per-vector 50 \
    --payload-types sqli,xss,cmdi,ssrf,xxe,deserialization,path_traversal,open_redirect \
    --request-timeout 30
docker compose logs dast-app
./stop.sh
```

---

## Configuración

Todo va a través de `src/core/config.py` (clase `Settings`, Pydantic BaseSettings).
Variables de entorno o `.env` para los valores por defecto; los flags de CLI tienen prioridad.
Nunca hardcodear URLs, rutas o credenciales en el código.

**cv/cp/rps son knobs de velocidad; depth/max-pages/max-payloads-per-vector/
payload-types/request-timeout son knobs de cobertura.** Los primeros cambian
cuán rápido y cuán visible es el escaneo; los segundos cambian qué se prueba
y, por tanto, el número de findings.

Velocidad / huella:

- `--concurrent-vectors` (env `CONCURRENT_VECTORS`, default `5`) — vectores en paralelo
- `--concurrent-payloads` (env `CONCURRENT_PAYLOADS`, default `10`) — payloads por scanner
- `--requests-per-second` (env `REQUESTS_PER_SECOND`, default `0`) — rate limit GLOBAL compartido entre todos los scanners (0 = sin límite)

Cobertura / alcance:

- `--depth` (env `MAX_DEPTH`, default `3`) — profundidad BFS del crawler
- `--max-pages` (env `MAX_PAGES`, default `100`) — tope absoluto de páginas
- `--max-payloads-per-vector` (env `MAX_PAYLOADS_PER_VECTOR`, default `50`) — palanca dominante de coste
- `--payload-types` (env `PAYLOAD_TYPES`, default CSV completo) — clases de scanner activas
- `--request-timeout` (env `REQUEST_TIMEOUT`, default `30`) — timeout HTTP por petición
- `--scanner-vector-timeout` (env `SCANNER_VECTOR_TIMEOUT_SECONDS`, default `120`) — tope de
  reloj por (vector × scanner). Bajarlo deja el escaneo avanzar más rápido
  ante endpoints atascados; subirlo da margen a payloads time-based
  (SLEEP/BENCHMARK) para confirmarse.

Cada `report.html`/`report.json` incluye un bloque "Effective Configuration"
con el dump completo de los Settings usados, para que el analista pueda
auditar la combinación efectiva.

`report.json` también expone `summary.scanner_health` con
`vector_timeouts`, `early_aborts`, `scanners_with_zero_valid_responses`
y `completion_rate_pct`. Cuando la tasa cae por debajo del 80% el HTML
muestra un banner amarillo "Scan degraded" — un escaneo con 0 findings
y `completion_rate_pct < 80` es sospechoso, no limpio. El JSON incluye
además `crawl_stats` con `crawl_limit_reason` (`max_pages_reached`,
`max_depth_reached` o `frontier_exhausted`) y `queued_unvisited` para
que el analista pueda decidir si subir `--max-pages` / `--depth`.

---

## Seguridad

- Logs sin strings de exploit en texto plano en reportes de producción
- Tráfico saliente del contenedor limitado por `entrypoint.sh` vía iptables
- No usar `shell=True` en subprocess
- Credenciales solo en `.env`, nunca commiteadas


## Prototipos de Commits Después de Cada Tarea

Al terminar cualquier tarea, muestra un bloque de commits y de git adds listo para copiar en el chat (NO lo ejecutes por bash). Mira primero el .gitignore, y para todos los archivos modificados que se encuentre en él, no los incluyas en los prototipos de commits. Formato:

---

**git adds y commits para esta tarea:**

Grupo 1 git
- `git add archivos`
- `git commit -m "<tipo>(<scope>): <descripción>"

Grupo 2 git
- `git add archivos`
- `git commit -m "<tipo>(<scope>): <descripción>"

Grupo 3 git
- `git add archivos`
- `git commit -m "<tipo>(<scope>): <descripción>"



---

Reglas:
- Usar formato Conventional Commits: `feat`, `fix`, `docs`, `test`, `refactor`, `ci`, `chore`.
- Un commit por cambio lógico (no agrupar todo en uno).
- Nunca ejecutar los comandos git — solo mostrarlos para hacer ctrl+c ctrl+v.
- Poner el bloque al final de la respuesta, después de todas las explicaciones.
- por cada grupo de archivos, indica el git add y su git commit. 
