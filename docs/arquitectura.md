# Arquitectura

Todo vive en `soc_tutor.py`, un solo archivo con la librería estándar de Python
más `anthropic` (que solo se importa cuando hace falta llamar a la API). El
diagrama del flujo (parseo local, plan, cuatro workers en paralelo y síntesis) está
en el [README](../README.md); aquí van los detalles que no caben ahí: formas de
datos, validación y decisiones.

## Parseo local

Soporta syslog clásico (`Oct  5 03:12:01 web01 sshd[2210]: ...`, el año es el
actual) y RFC 3339 (`2026-10-05T03:12:01.123456+00:00 web01 ...`, se trunca a
segundos y se ignora la zona).

Cada línea no vacía produce **un** evento; si no tiene formato syslog, el
evento es de tipo `otro` con `ts` y `hora` en `null`. `n` es el número de línea
físico (empieza en 1; las líneas vacías cuentan para la numeración pero no
generan evento).

```
{"n": 15, "ts": "2026-10-05T03:12:44", "hora": "03:12:44", "tipo": "acceso",
 "usuario": "deploy", "ip": "203.0.113.45", "detalle": "Acceso exitoso de ...",
 "inexistente": false}
```

| tipo | qué detecta |
|---|---|
| `fallo` | `Failed password for [invalid user] USER from IP` (`inexistente` si dice "invalid user") |
| `acceso` | `Accepted <método> for USER from IP` |
| `sudo` | línea de `sudo` con `COMMAND=`; el usuario es quien invoca |
| `descarga` | un `sudo` cuyo comando contiene `wget` o `curl`; `ip` es la de la URL, si hay |
| `cuenta_nueva` | `useradd: new user: name=USER` (la línea `new group` queda como `otro`) |
| `grupo` | `usermod: add 'USER' to group 'GRUPO'` (la de `shadow group` queda como `otro`) |
| `password` | `password changed for USER` |
| `otro` | todo lo demás |

**IP sospechosa**: una IP con 5 o más eventos `fallo` (`UMBRAL_FUERZA_BRUTA`).
Para cada una se busca el primer `acceso` posterior desde esa IP y las
*acciones posteriores*: eventos después de ese acceso, que no sean `otro`, cuyo
usuario sea el comprometido o una cuenta creada después (`cuenta_nueva`), o cuya
IP sea la sospechosa. En el log de ejemplo son L17, L19, L20, L22 a L24, L26 a
L29 y L31; el acceso de `ana` desde una IP interna (L33 a L35) queda fuera.

```
parseo = {
  "eventos": [...],
  "ips_sospechosas": [{"ip", "fallos", "usuarios": [...], "usuarios_inexistentes": [...],
                       "lineas_fallos": [ini, fin],
                       "acceso": {"n", "usuario", "metodo"} | null,
                       "acciones_posteriores": [n, ...]}],
  "estadisticas": {"total_lineas": int, "por_tipo": {tipo: cantidad}}
}
```

`total_lineas` cuenta líneas con contenido. `log_lineas` (la lista de texto
crudo, un elemento por línea física, vacías incluidas) es lo que se usa como
límite al validar referencias.

## Evidencia condensada

Es lo único que sale de la máquina, junto con las estadísticas y las IPs
sospechosas. Los fallos consecutivos con la misma IP y usuario se vuelven una
línea; el resto, una línea por evento (recortada a 300 caracteres):

```
L3-L4 03:12:01→03:12:04 [fallo x2] Failed password for invalid user admin from 203.0.113.45 (usuario inexistente)
L15 03:12:44 [acceso] sshd: Accepted password for deploy from 203.0.113.45 port 51121 ssh2
```

Eso incluye IPs, usuarios, comandos de `sudo` completos con sus rutas y huellas de
claves SSH. El hostname de las líneas syslog no se envía (se descarta al
parsear); una línea sin formato syslog sí va entera, recortada.

## Llamadas a la API

Todas pasan por `llamar_api`, que usa `client.messages.stream(...)`, no pasa
`temperature` ni otros parámetros opcionales y registra una fila de métricas por
llamada, protegida con un candado porque los workers corren en hilos.

- `max_tokens`: plan 8000, workers 16000, síntesis 32000. Se subieron tras las
  primeras ejecuciones reales: con la mitad, las respuestas largas se cortaban y
  cada corte costaba un reintento.
- La primera línea del prompt de usuario es `TAREA: <nombre>`
  (`planificacion`, `linea_tiempo`, `mitre_indicadores`, `contencion_erradicacion`,
  `recuperacion_mejoras`, `sintesis`). El cliente falso de las pruebas enruta por ahí.
- Roles de métricas: `orquestador_plan`, los cuatro workers y `orquestador_sintesis`.
  Un reintento es otra fila con el sufijo ` (reintento)`. Cada fila:
  `{"rol", "modelo", "tokens_in", "tokens_out", "segundos"}`.
- Modelos por defecto: `claude-opus-5-5` (orquestador) y `claude-sonnet-5-5`
  (workers); se cambian con `--orquestador` y `--worker`.

**Extracción de JSON**: se quitan las cercas ```` ``` ````, se toma desde la
primera `{` hasta la última `}` y, si eso no es JSON válido, se prueba de `[` a
`]` (una `linea_tiempo` devuelta como lista se envuelve en `{"linea_tiempo": [...]}`).

**Reintento**: si la respuesta no es JSON válido o no pasa la validación, se
repite la llamada **una vez** con el mismo prompt más una línea que empieza por
`REINTENTO:` con el motivo. Si la respuesta parece cortada (`stop_reason ==
"max_tokens"` o JSON sin cerrar), esa línea pide una versión más concisa.

## Salida esperada de cada nodo

```
plan                     {"clasificacion": {"tipo", "severidad": "baja|media|alta|crítica", "justificacion"},
                          "instrucciones": {<worker>: str, ...}}
linea_tiempo             {"linea_tiempo": [{"lineas": [ini, fin], "hora", "titulo", "explicacion", "tipo"}]}
mitre_indicadores        {"mitre": [{"id", "nombre", "tactica", "lineas": "L3-L14", "por_que"}],
                          "indicadores": [{"texto", "lineas"}], "no_concluible": [str]}
contencion_erradicacion  {"fases": [{"nombre": "Preservar evidencia"|"Contención"|"Erradicación",
                                     "pasos": [{"texto", "comando", "requiere_aprobacion": bool}]}]}
recuperacion_mejoras     {"fases": [{"nombre": "Recuperación y verificación", "pasos": [...]}],
                          "escalamiento": [str], "mejoras": [str]}
sintesis                 el reporte final (claves de `reporte.json` que genera el modelo)
```

`tactica` va en español, una o varias separadas por coma, de la lista `TACTICAS`
del código (Acceso inicial, Ejecución, Persistencia, ..., Exfiltración, Impacto).

## Validación

Las respuestas de los modelos no se aceptan tal cual. Hay dos niveles:

**Tolerante** (se corrige en silencio, sin gastar un reintento):

- Nombres de fase sin tilde o en otras mayúsculas (`"Contencion"` pasa a
  `"Contención"`) y fases reordenadas; las repetidas se unen.
- Severidad (`"Critica"`), tácticas (`"ACCESO INICIAL"`) y `tipo` de evento
  normalizados al nombre canónico; una táctica desconocida se conserva tal cual
  y un `tipo` desconocido pasa a `otro`.
- Hora `"3:12:01"` pasa a `"03:12:01"`; `"03:12"` pasa a `"03:12:00"`.
- `requiere_aprobacion` acepta `true`/`false`/`sí`/`no` como texto; si falta, vale
  `true` por seguridad.
- `lineas` como `[ini, fin]`, lista de números o texto con `L#`; elementos de
  lista como texto o como `{"texto": ...}`; `comando` como lista de líneas.

**Estricto** (falla y dispara el reintento):

- Referencias de `lineas` fuera de `1..N` (N = líneas del log) o ausentes donde
  son obligatorias.
- Campos de texto vacíos, listas de pasos vacías, estructuras de otro tipo.
- `requiere_aprobacion` con un valor que no es booleano ni true/false/sí/no.
- Severidad fuera de la lista, o faltan fases canónicas (salvo en la síntesis
  cuando algún worker falló, porque entonces puede faltar su parte).

La validación solo comprueba el campo `lineas` de cada elemento. Las
referencias `L#` escritas dentro de textos libres (`explicacion`, `por_que`,
`justificacion`) no se verifican; el dashboard las vuelve enlaces y, si una
apunta fuera del log, el salto se limita a la última línea.

## Fallos

`correr_nodo` nunca lanza: guarda el error en el resultado del nodo.

- **Falla un worker** (excepción o JSON inválido tras el reintento): los demás
  siguen. La síntesis recibe la lista de fallidos, lo indica en
  `correcciones_orquestador` y `workers_fallidos` lo registra.
- **Falla la planificación**: sin clasificación no hay pipeline; el programa sale
  con código 1. En `--serve` emite `error` y `fin` y el servidor sigue activo
  hasta Ctrl+C.
- **Falla la síntesis**: el código une las salidas de los workers
  (playbook = fases de contención y recuperación) con una única corrección,
  `"La síntesis del orquestador falló (...); este reporte une la salida de los workers sin revisión."`,
  y `pipeline.sintesis.estado` queda en `"error"`.

## `reporte.json`

```
{
  "clasificacion", "linea_tiempo", "mitre", "indicadores", "no_concluible",
  "playbook": {"fases": [...]}, "escalamiento", "mejoras", "correcciones_orquestador",
                                        # lo anterior lo produce la síntesis
  "parseo", "log_lineas", "metricas",   # lo añade el código
  "pipeline": {"plan"|<worker>|"sintesis": {"estado": "listo"|"error", "modelo", "instruccion",
                                            "salida": obj|null, "error": str|null,
                                            "tokens_in", "tokens_out", "segundos"}},
  "workers_fallidos": [...], "workers_segundos_reloj": float,
  "modelos": {"orquestador", "worker"}, "archivo_log": "nombre.log", "generado": "ISO",
  "_demo": true                         # solo en el reporte de demostración
}
```

- En `pipeline`, tokens y segundos suman el reintento.
- `salida` del plan es su JSON; la de la síntesis es `{"correcciones_orquestador": [...]}`
  (el reporte completo ya está en las claves de primer nivel).
- `archivo_log` guarda solo el **nombre** del archivo, no la ruta, para no
  filtrar carpetas del usuario en reportes y dashboards compartidos.
- Contiene el texto crudo del log (`log_lineas`): trátalo como el log original.

## Eventos SSE

`--serve` expone `GET /events` (`text/event-stream`); cada mensaje es
`data: <json en una línea>`.

| `tipo` | contenido |
|---|---|
| `inicio` | `parseo`, `log_lineas`, `modelos`, `archivo_log` |
| `nodo` | `nodo` (`plan`, un worker o `sintesis`), `estado` (`ejecutando`, `listo`, `error`), `modelo`, `instruccion`; con `listo` o `error` también `salida`, `error`, `tokens_in`, `tokens_out`, `segundos` |
| `reporte` | `reporte`: el reporte completo |
| `error` | `mensaje` |
| `fin` | sin más datos |

El servidor guarda el historial y lo reenvía completo a cada conexión nueva
(recargar la página no pierde nada), manda `: ping` cada 15 s y cierra el stream
tras `fin`. El pipeline arranca con la **primera** conexión a `/events`, para que
la animación se vea en vivo. El navegador cierra el `EventSource` al recibir `fin`.

## Dashboard

`DASHBOARD_HTML`, al final de `soc_tutor.py`, es una plantilla HTML con CSS y JS
vanilla y SVG inline, sin CDNs ni fuentes externas (funciona sin internet). Tiene
dos marcadores, `const DATOS = __DATOS__;` y `const MODO = "__MODO__";`, que
`renderizar_dashboard` sustituye:

- `DATOS`: el reporte como JSON (o `null`) con `<`, `>`, `&`, U+2028 y U+2029
  escritos como `\u003c`, `\u003e`, `\u0026`, `\u2028` y `\u2029`, de modo que
  ningún texto del log o de un modelo pueda cerrar el `<script>`. Se sustituye `__MODO__` antes que `__DATOS__`, así
  un `__MODO__` dentro de los datos no se toca.
- `MODO`: `estatico` (`dashboard.html` con los datos embebidos), `replay`
  (`--replay`, datos embebidos servidos por HTTP) y `vivo` (`--serve`, `DATOS` es
  `null` y el JS abre `EventSource("/events")`).

Si el reporte trae `"_demo": true`, el dashboard muestra un banner.

El servidor HTTP (`http.server`, un hilo por conexión) escucha solo en
`127.0.0.1:8000`; el puerto es fijo. Además valida las cabeceras `Host` y `Origin`
(esta última solo si el navegador la envía): responde 403 si no apuntan a `localhost`
o `127.0.0.1` con el puerto del servidor. Así una web externa no puede leer el
dashboard (que contiene el log) mediante *DNS rebinding*, ni disparar el pipeline,
y con él gasto de créditos, desde otra pestaña.

## Pruebas

`python -B -m unittest discover -s tests -v`. `tests/test_soc_tutor.py` cubre el
parseo, los validadores, el escape del dashboard, el servidor SSE (en un puerto
libre al azar) y el pipeline completo ejecutando `soc_tutor.py` como subproceso en
una carpeta temporal. `tests/test_seguridad_servidor.py` cubre la validación de
`Host`/`Origin`.

El camino de la API usa el paquete `anthropic` falso de `tests/fake/`, que se
antepone con `PYTHONPATH`. Imita solo `client.messages.stream(...).get_final_message()`,
enruta por la línea `TAREA:` y devuelve respuestas pregrabadas
(`tests/fake/respuestas.py`) que incluyen errores sembrados a propósito para que
la síntesis los corrija. Se controla con variables de entorno:

| variable | valores |
|---|---|
| `FAKE_ESCENARIO` | `normal` (por defecto), `reintento` (un JSON inválido que se arregla al reintentar), `falla_worker` (un worker falla siempre), `falla_sintesis` |
| `FAKE_DEMORA` | factor de la demora simulada; `0` no duerme |

Las pruebas usan `FAKE_DEMORA=0`. `tests/generar_reporte_demo.py` usa ese mismo
cliente con `FAKE_DEMORA=1` para regenerar `reportes/reporte_demo.json` con duraciones
simuladas (así las barras de tiempo del dashboard no salen vacías) y le añade `_demo`
y `_nota`.

Lo que las pruebas **no** cubren: llamadas reales a la API, el JS del dashboard
(no hay pruebas de navegador en este repo) y `--serve` / `--replay` de extremo a
extremo sobre el puerto 8000.

## Decisiones

- **Un solo archivo y solo stdlib**: se copia, se lee y se ejecuta sin instalar
  nada salvo `anthropic`. El coste es un archivo largo (la mayor parte es la
  plantilla del dashboard).
- **Parseo local antes que IA**: los números de línea, los conteos y las IPs
  sospechosas salen de regex, deterministas y comprobables; los modelos explican,
  no cuentan.
- **Evidencia condensada y workers en paralelo**: menos tokens y menos datos
  fuera de la máquina; el tiempo total se parece al del worker más lento y la
  segunda pasada del orquestador filtra afirmaciones sin respaldo.
- **Validar y normalizar, no solo `json.loads`**: los modelos varían en forma
  (tildes, horas, listas o textos); lo inofensivo se corrige y lo que cambia el
  significado se rechaza y se reintenta.
- **Los comandos del playbook nunca se ejecutan**: son texto para que una
  persona los revise; los que pueden afectar al servicio llevan `requiere_aprobacion`.
- **`127.0.0.1`, no `0.0.0.0`**, y con validación de `Host`/`Origin`: el
  dashboard contiene el log, así que no se expone a la red ni a otras webs.
