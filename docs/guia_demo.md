# Guía para la demo

Pensada para presentar SOC Tutor en unos minutos, con un plan B si falla el wifi.
Ensáyala completa una vez antes de presentar.

## Antes del evento (con internet)

1. `pip install anthropic` y la clave en `ANTHROPIC_API_KEY` (variable de entorno;
   no la pegues en un archivo ni la muestres en pantalla).
2. `python soc_tutor.py ejemplo_auth.log --dry-run`: confirma que Python y el log
   funcionan. No usa la API.
3. Corre el pipeline una vez completo: `python soc_tutor.py ejemplo_auth.log`.
   Deja `reportes/reporte.json`, `reporte.md` y `dashboard.html` con datos reales de
   tu ensayo. Son tu respaldo; `reportes/` no se sube a git, así que se genera en
   cada máquina. Con el log de ejemplo (sintético) no hay riesgo; con un log real,
   trabaja fuera de carpetas sincronizadas (OneDrive, Dropbox), porque `.gitignore`
   evita git pero no la sincronización.
4. Libera el puerto 8000 (la herramienta no permite cambiarlo) y prueba que el
   dashboard se vea bien a pantalla completa y con zoom, como lo verá el público.
5. Opcional: `python -B -m unittest discover -s tests` (usa un cliente falso, no gasta créditos).

## Orden en vivo

1. **Parseo local**: `python soc_tutor.py ejemplo_auth.log --dry-run`. Enseña el
   resumen (12 fallos, 5 a usuarios inexistentes, acceso en L15) y la evidencia
   condensada. Mensaje: esto lo calcula el código con regex y es lo único que se
   manda a los modelos.
2. **Análisis en vivo**: `python soc_tutor.py ejemplo_auth.log --serve` y abre
   http://localhost:8000 (no abre el navegador solo). El pipeline arranca al abrir
   la página: los nodos pasan de pendiente a ejecutando a listo. Los cuatro
   workers se encienden a la vez.
3. **Recorrido del dashboard** con "Modo explicado" activado (abajo).
4. **Cierre**: vuelve a la consola, enseña la tabla de tokens y segundos por rol y
   los archivos guardados en `reportes/`. El tiempo depende de la API; no
   prometas una duración.

## Plan B sin wifi

El pipeline necesita internet para llegar a la API, así que sin conexión no hay
análisis nuevo. Lo que sí funciona, de mejor a peor:

| opción | cómo | notas |
|---|---|---|
| Tu corrida de ensayo, sin servidor | abre `reportes/dashboard.html` con doble clic | un solo archivo con los datos embebidos; no necesita servidor ni internet |
| Tu corrida de ensayo, con servidor | `python soc_tutor.py --replay reportes/reporte.json` y http://localhost:8000 | igual que la anterior, servida en local |
| Reporte de demostración | `python soc_tutor.py --replay reportes/reporte_demo.json` | viene en el repo; el dashboard muestra un banner "Datos de demostración..." |

Si usas el reporte de demostración, dilo: sus respuestas están escritas de
antemano (las generó un cliente falso, no la API), los tokens son estimaciones y
las duraciones, simuladas. No presentes la sección Métricas como mediciones reales.

Si la API deja de responder en mitad de la demo, no esperes: pasa al plan B.

## Qué narrar con "Modo explicado"

El botón muestra bajo cada sección una nota breve ("qué es" y "por qué importa").
Puedes leerla o parafrasearla. Orden de la página y una idea por sección:

1. **Encabezado**: tipo, severidad y justificación que decidió Opus. La
   justificación cita líneas del log: se puede comprobar, no hay que creerla.
2. **Pipeline de agentes**: Opus planifica, cuatro Sonnet trabajan en paralelo,
   Opus revisa. Haz clic en un nodo para ver qué se le pidió y qué respondió.
3. **Línea de tiempo**: la ráfaga de fallos, el login exitoso y, justo después,
   actividad administrativa: la señal clásica de compromiso. Pasa el cursor para
   ver la línea cruda; haz clic en un punto para abrir "Explícame esto" con la
   explicación del tutor y la técnica MITRE.
4. **Visor del log** (columna lateral): cada `L#` de cualquier texto es un
   enlace. Haz clic en uno, por ejemplo L15, y la línea parpadea. Si algo no se
   puede señalar en el log, no debería afirmarse.
5. **Cadena MITRE**: una columna apagada significa "sin evidencia en este log",
   no "descartado".
6. **Playbook**: preservar evidencia va primero porque contener o erradicar puede
   destruirla. Marca algún paso (sube la barra de progreso), copia un comando y
   señala un ⚠️: esos pasos los debe aprobar una persona. La herramienta no
   ejecuta nada.
7. **Qué corrigió Opus**: lo que cambió respecto a los workers y lo que el log no
   permite concluir. Es el argumento de la segunda pasada del orquestador.
8. **Métricas**: tokens y segundos por rol y totales Opus frente a Sonnet; el
   tiempo de los workers se parece al del más lento porque corren en paralelo.

## Si preguntan

- **¿Qué sale de mi máquina?** La evidencia condensada (líneas del log recortadas
  a 300 caracteres, estadísticas e IPs sospechosas): IPs, usuarios, comandos de
  `sudo` completos con sus rutas y huellas de claves SSH. El hostname de las líneas
  syslog no se envía. Con un log real, anonimiza antes. El de ejemplo es sintético
  (IPs de documentación y la privada `10.0.0.25`).
- **¿Ejecuta los comandos?** No. Son sugerencias para revisar.
- **¿Y si un worker falla?** Los demás siguen y el reporte lo indica; si falla la
  síntesis, el código une lo que entregaron los workers sin revisión y lo avisa.
