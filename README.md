# SOC Tutor

Herramienta 100% defensiva. Lee un `auth.log` de Linux, explica qué pasó como lo
haría un analista SOC senior ante un junior, genera un playbook de respuesta a
incidentes y lo muestra en un dashboard web. No hace nada ofensivo y no toca
ningún servidor: solo analiza un archivo de texto que le das (y, salvo en
`--dry-run` y `--replay`, envía su evidencia condensada a la API de Anthropic).

## Cómo funciona

```
  auth.log --> parseo local (regex, sin IA)
     v
  evidencia condensada (L#, rangos, conteos)
     v
  Orquestador Opus 5.5: clasifica y planifica
     +---------------+---------------+---------------+
     v               v               v               v
  Sonnet 5.5      Sonnet 5.5      Sonnet 5.5      Sonnet 5.5
  línea de        MITRE e         contención y    recuperación
  tiempo          indicadores     erradicación    y mejoras
     +---------------+---------------+---------------+
     v
  Orquestador Opus 5.5: síntesis y revisión
     v
  reporte.json   reporte.md   dashboard
```

Los 4 workers corren en paralelo; si uno falla, los demás siguen y el reporte lo
indica. Opus revisa los resultados y quita lo que la evidencia no respalda.

**Por qué evidencia condensada:** a los modelos no se les manda el log entero,
sino una versión resumida: varios fallos seguidos de la misma IP y usuario se
vuelven una sola línea con su rango y conteo (`L3-L4 [fallo x2]`). Así se gastan
menos tokens y cada afirmación se puede citar con referencias `L#` que puedes
verificar en el log original.

## Requisitos

- Python 3.10 o superior (probado con 3.13).
- `pip install anthropic`. Es la única dependencia y solo hace falta para el
  pipeline con IA; `--dry-run` y `--replay` no la necesitan.
- La variable `ANTHROPIC_API_KEY`: `$env:ANTHROPIC_API_KEY = "tu-clave"` en
  PowerShell o `export ANTHROPIC_API_KEY="tu-clave"` en bash.

## Uso

```
python soc_tutor.py ejemplo_auth.log --dry-run
python soc_tutor.py ejemplo_auth.log
python soc_tutor.py ejemplo_auth.log --serve
python soc_tutor.py --replay reportes/reporte.json
python soc_tutor.py --replay reportes/reporte_demo.json
```

1. `--dry-run`: solo parseo local. Imprime el resumen y la evidencia condensada.
2. Sin flags: pipeline completo. Guarda `reportes/` e imprime la tabla rol |
   modelo | tokens in | tokens out | segundos, con el total por modelo.
3. `--serve`: dashboard en vivo en http://localhost:8000. El pipeline arranca al
   abrir la página y los nodos se encienden a medida que avanza. Al terminar
   guarda `reportes/` como en el modo anterior.
4. `--replay reportes/reporte.json`: dashboard con un reporte guardado, sin API.
5. `--replay reportes/reporte_demo.json`: reporte de demostración escrito a mano
   (no lo generó la API), para ver el dashboard sin gastar créditos. El
   dashboard lo marca con un banner.

`--serve` y `--replay` escuchan solo en `127.0.0.1:8000` (puerto fijo). Modelos:
`--orquestador` (por defecto `claude-opus-5-5`) y `--worker` (`claude-sonnet-5-5`).

## Qué genera (carpeta `reportes/` del directorio actual)

- `reporte.json`: reporte completo, con parseo, líneas del log y métricas.
- `reporte.md`: versión legible.
- `dashboard.html`: un solo archivo con los datos embebidos. Abre con doble
  clic, sin servidor ni internet. Es el respaldo para la demo.

## Qué ves en el dashboard

- Encabezado con tipo de incidente, severidad y justificación.
- Pipeline en vivo con estado, tokens y segundos por nodo; clic en un nodo para
  ver su instrucción y su salida.
- Línea de tiempo con la línea cruda en el tooltip; clic en un evento abre
  "Explícame esto" con la explicación del tutor y la técnica MITRE.
- Visor del log con líneas resaltadas por tipo. Cada `L#` o `L#-L#` del
  dashboard es un enlace que lleva a esa línea y la hace parpadear.
- Cadena MITRE: tácticas y técnicas detectadas, con sus líneas.
- Playbook por fases con checklist y barra de progreso; comandos con botón de
  copiar y ⚠️ con aviso en los pasos que necesitan aprobación. Incluye
  escalamiento y mejoras.
- "Qué corrigió Opus": cambios respecto a los workers y lo no concluible.
- Métricas de tokens y tiempo por rol, y totales Opus vs Sonnet.
- Botón "Modo explicado": muestra u oculta notas sobre cada sección.

## Formatos de log soportados

- Syslog clásico de Debian/Ubuntu: `Oct  5 03:12:01 web01 sshd[2210]: ...`
- RFC 3339 (Ubuntu 23.10+): `2026-10-05T03:12:01+00:00 web01 sshd[2210]: ...`

Prueba primero tu log con `--dry-run`. Antes de enviarlo a la API, anonimiza lo
que sea real: la evidencia condensada sale de tu máquina e incluye IPs, usuarios,
comandos de `sudo` completos con sus rutas y huellas de claves SSH (el hostname de
las líneas syslog no se envía).

## Seguridad

- Los comandos del playbook son sugerencias para revisar; la herramienta no
  ejecuta ninguno. Los marcados con ⚠️ requieren aprobación antes de correrlos.
  Esa marca la pone el modelo, y un log manipulado podría inducirlo a error:
  revisa cada comando antes de copiarlo, aunque no lleve ⚠️.
- Inyección de prompt: parte del auth.log la controla el atacante (por ejemplo,
  el usuario de un `ssh "texto"@host` queda escrito en el log). Por eso la
  evidencia llega a los modelos dentro de `<evidencia_log>…</evidencia_log>`,
  las reglas les indican que ese bloque son datos y no instrucciones, y si una
  línea intenta darles órdenes deben reportarla como indicador ("posible log
  manipulado") con su L#. Si el log trae esas etiquetas, se neutralizan para que
  no puedan cerrar el bloque. Esto reduce el riesgo, no lo elimina: un modelo
  aún puede equivocarse, así que la revisión humana de los comandos sigue siendo
  necesaria.
- `ejemplo_auth.log` es sintético. Usa IPs de documentación (RFC 5737:
  `203.0.113.x` y `198.51.100.x`) y una IP privada, `10.0.0.25`, como contraste.
- `reportes/` incluye el texto del log analizado: no lo compartas sin anonimizar.
  `.gitignore` lo excluye (salvo el reporte de demostración), igual que los `*.log`.
  Evita git, pero no la sincronización: analiza logs reales fuera de carpetas de
  OneDrive, Dropbox o similares.

## Pruebas

```
python -B -m unittest discover -s tests -v
```

Usan un cliente falso de `anthropic` (`tests/fake/`): no necesitan clave ni
internet y no gastan créditos. Cubren el parseo, los validadores, el escape del
dashboard y el pipeline en cuatro escenarios (normal, reintento, falla de un
worker y falla de la síntesis). `-B` evita crear `__pycache__`.

## Documentación y licencia

- [docs/arquitectura.md](docs/arquitectura.md): flujo, datos, validación y decisiones.
- [docs/guia_demo.md](docs/guia_demo.md): cómo presentarla, con plan B sin wifi.
- [docs/prompt_original.md](docs/prompt_original.md): el enunciado del Build Day.

Licencia MIT, ver [LICENSE](LICENSE).
