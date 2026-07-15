# `cf-sim` — simulador de `cf_clearance`

## Qué simula

`cf-sim` es un servicio FastAPI que imita el **contrato mínimo** del
mecanismo `cf_clearance` de Cloudflare, colocado delante de `dvwa-origin`:

1. Emite una cookie `cf_clearance` solo tras un **challenge JavaScript**
   que requiere un navegador real (necesita `navigator` y `btoa`).
2. Liga la cookie al **`User-Agent`** que la solicitó.
3. Devuelve **HTTP 403** con un header marcador `X-Cf-Sim-Challenge` si la
   cookie falta, es desconocida, está caducada o el UA no coincide.
4. Si la cookie es válida, hace de **reverse proxy** hacia el backend DVWA.

Toma el alias de red `dvwa-cf` en el compose; el puerto host es `8089`.

## Qué NO simula

- **No** imita TLS / JA3 / JA4 fingerprinting.
- **No** implementa Turnstile real ni el Bot Management de Cloudflare.
- **No** hace rate limiting ni scoring de comportamiento.

La propagación de `User-Agent` + cookies cubre el grueso del contrato de
Cloudflare en planes estándar, que es lo que el bridge Crawler→Fuzzer del
DAST necesita validar.

## El header `X-Cf-Sim-Challenge`

Es la API del simulador hacia el `HTTPClient` del DAST. Valores posibles:

| Valor           | Significado                                  | El bridge debe… |
|-----------------|----------------------------------------------|-----------------|
| `missing`       | No hay cookie `cf_clearance`                 | refrescar       |
| `expired`       | La cookie existía pero ha caducado           | refrescar       |
| `invalid_token` | La cookie no corresponde a ninguna sesión    | fallo permanente |
| `ua_mismatch`   | La cookie fue emitida para otro `User-Agent` | fallo permanente |

## Cómo se ejerce

- **Desde un navegador real (Playwright):** el 403 inicial trae un
  `<meta http-equiv="refresh">` que lleva a `/cdn-cgi/challenge-page`; ahí
  un script computa el valor y lo envía por POST; el simulador responde con
  `Set-Cookie: cf_clearance=...` y un 302 al path original. Todo fluye
  automáticamente.
- **Desde `httpx` a pelo:** sin bridge → 403 permanente (httpx no ejecuta
  JS). Con `--cf-clearance-mode=refresh`, el `HTTPClient` relanza Playwright
  para renovar la cookie cuando ve `expired`/`missing`; con `propagate` se
  reusa la cookie inicial sin refresh; con `off` el fuzzer corre sin sesión
  y recibe 403 en todas las requests.

## Configuración (env vars)

| Variable                | Default                   | Descripción                       |
|-------------------------|---------------------------|-----------------------------------|
| `BACKEND`               | `http://dvwa-origin:80`   | Backend al que se hace proxy      |
| `CLEARANCE_TTL_SECONDS` | `1800`                    | Vida de la cookie (30 min, igual que el default real de Cloudflare) |

Para los tests de expiración se baja `CLEARANCE_TTL_SECONDS` a un valor
pequeño (p.ej. `2`) y se espera a que la cookie caduque.

## Limitaciones conocidas

El estado (`valid_tokens`) vive **en memoria**: reiniciar el contenedor
invalida todas las cookies emitidas. Es intencional — es un fixture de
pruebas, no un servicio de producción.
