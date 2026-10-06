# Prompt original del Build Day

Este es el enunciado que se dio a Claude en el Build Day 2.0 (Opus y Sonnet)
para construir SOC Tutor. Se conserva sin cambios, como referencia de los
requisitos de partida. La herramienta final puede diferir en detalles; la
referencia vigente es el [README](../README.md) y
[arquitectura.md](arquitectura.md).

---

Construye en esta carpeta una herramienta en Python (un solo archivo soc_tutor.py + README.md), 100% defensiva, que lee un auth.log de Linux, explica qué pasó como lo haría un analista SOC senior ante un junior (tutor de logs), genera un playbook de respuesta a incidentes y lo muestra en un dashboard web interactivo y explicativo. La arquitectura es orquestador + subagentes: Opus 5.5 planifica y revisa; 4 workers con Sonnet 5.5 trabajan en paralelo.

RESTRICCIONES
- Solo la librería anthropic como dependencia externa. Backend con la librería estándar (http.server + SSE). Sin Flask, sin servidores externos, sin instalar nada más.
- Dashboard en un solo archivo HTML con CSS y JS vanilla y SVG inline. Sin frameworks ni CDNs (el wifi del evento puede fallar).
- Importa anthropic solo cuando no es --dry-run. La clave se lee de ANTHROPIC_API_KEY; si falta, sal con un mensaje claro.
- Todo es defensivo: nada ofensivo, nada que toque servidores reales.
- Código simple y legible, sin sobreingeniería.

USO
python soc_tutor.py ejemplo_auth.log --dry-run        # solo parseo local, sin API
python soc_tutor.py ejemplo_auth.log                  # pipeline completo, genera reportes/
python soc_tutor.py ejemplo_auth.log --serve          # dashboard en vivo en http://localhost:8000
python soc_tutor.py --replay reportes/reporte.json    # dashboard con datos guardados, SIN llamar a la API
Opciones: --orquestador (por defecto claude-opus-5-5) y --worker (por defecto claude-sonnet-5-5).

PASO 1 — LOG DE EJEMPLO
Crea ejemplo_auth.log, sintético y realista (~35 líneas, formato syslog Debian/Ubuntu): fuerza bruta SSH desde una IP de documentación (203.0.113.x) contra usuarios inexistentes, root y un usuario real; login exitoso tras los fallos; luego sudo con comandos sospechosos, creación de un usuario nuevo y alta en el grupo sudo, cambio de contraseña, descarga y ejecución de un script desde otra IP (198.51.100.x) y un login posterior por clave pública con la cuenta nueva. Al final, un login normal desde una IP interna para contrastar.

PASO 2 — PARSEO LOCAL (sin IA)
Regex para: fallos de login (marca usuario inexistente), accesos exitosos, sudo, useradd, usermod a grupo, cambio de password. Guarda número de línea, hora y tipo (fallo, acceso, sudo, cuenta_nueva, grupo, password, descarga, otro). Detecta IPs con 5 o más fallos, accesos exitosos posteriores desde esa IP y las acciones posteriores al acceso.

PASO 3 — EVIDENCIA CONDENSADA
Agrupa fallos consecutivos (misma IP y usuario) en una línea con rango (L#-L#) y conteo. Esa evidencia, más las estadísticas del parseo, es lo único que se envía a los modelos (menos tokens y evidencia citable).

PASO 4 — ORQUESTADOR, PLANIFICACIÓN (Opus)
Recibe la evidencia y devuelve SOLO JSON válido con: clasificacion {tipo, severidad, justificacion} y una instrucción específica para cada worker: "linea_tiempo", "mitre_indicadores", "contencion_erradicacion", "recuperacion_mejoras". Valida el JSON; si falla, reintenta una vez.

PASO 5 — WORKERS (Sonnet), LOS 4 EN PARALELO (ThreadPoolExecutor)
Cada uno recibe la evidencia, la clasificación y su instrucción, escribe en español, cita solo evidencia presente con referencias L# o L#-L#, y devuelve SOLO JSON válido (valida y reintenta una vez):
- linea_tiempo: lista de {lineas:[ini,fin], hora, titulo, explicacion (tono de tutor, para un junior), tipo}.
- mitre_indicadores: {mitre:[{id, nombre, tactica, lineas, por_que}], indicadores:[{texto, lineas}], no_concluible:[...]}.
- contencion_erradicacion: {fases:[{nombre, pasos:[{texto, comando, requiere_aprobacion}]}]} con las fases "Preservar evidencia", "Contención" y "Erradicación"; comandos Linux defensivos concretos.
- recuperacion_mejoras: {fases:[{nombre:"Recuperación y verificación", pasos:[...]}], escalamiento:[...], mejoras:[...]}.
Solo medidas defensivas. Lo supuesto se marca como "supuesto". Si un worker falla, los demás siguen y el orquestador lo indica en el reporte.

PASO 6 — ORQUESTADOR, SÍNTESIS Y REVISIÓN (Opus)
Recibe los 4 resultados y la evidencia. Detecta contradicciones, elimina afirmaciones no respaldadas por la evidencia, completa huecos y devuelve el reporte final como JSON válido con esta forma, incluyendo correcciones_orquestador (lista de lo que cambió respecto a los workers):
{
  clasificacion: {tipo, severidad, justificacion},
  linea_tiempo: [...], mitre: [...], indicadores: [...], no_concluible: [...],
  playbook: {fases: [...]},
  escalamiento: [...], mejoras: [...],
  correcciones_orquestador: [...]
}
Después agrega, desde el código (no desde el modelo): parseo {eventos:[{n, ts, tipo, usuario, ip, detalle}], ips_sospechosas}, log_lineas (texto crudo de cada línea) y metricas [{rol, modelo, tokens_in, tokens_out, segundos}]. Guarda reportes/reporte.json y también reportes/reporte.md legible. Usa un helper único para las llamadas a la API que registre las métricas (rol, modelo, tokens, segundos).

PASO 7 — MODOS
--dry-run: imprime el resumen del parseo y la evidencia condensada.
(sin flags): corre el pipeline, guarda reporte.json, reporte.md y dashboard.html, e imprime la tabla rol | modelo | tokens in | tokens out | segundos con total por modelo.
--serve: levanta http://localhost:8000 con http.server en un hilo, sirve el dashboard, corre el pipeline en segundo plano y transmite eventos por SSE (orquestador planificando, cada worker iniciado/terminado con tokens y segundos, síntesis, reporte final). Al terminar guarda dashboard.html autocontenido con los datos embebidos (abre sin servidor; respaldo para la demo).
--replay: sirve el dashboard con un reporte.json guardado, sin llamar a la API (para iterar en la interfaz sin gastar créditos).

PASO 8 — DASHBOARD (tema oscuro, responsive, legible proyectado)
a) Encabezado: tipo de incidente, badge de severidad y justificación (del orquestador).
b) Pipeline animado: nodos Orquestador (Opus) → 4 workers Sonnet en paralelo → Síntesis (Opus). Estados pendiente/ejecutando/listo en vivo, con tokens y segundos; al hacer clic en un nodo se ve su instrucción y su salida.
c) Línea de tiempo interactiva (SVG): eventos sobre el eje horario, color por tipo; tooltip con la línea cruda; el clic abre una tarjeta "Explícame esto" con la explicación del tutor y la técnica MITRE asociada.
d) Visor del log: el auth.log con líneas resaltadas por tipo. Todo "L#" o rango "L#-L#" que aparezca en cualquier texto del dashboard es un enlace que hace scroll y parpadea esa línea en el visor (evidencia trazable).
e) Cadena de ataque MITRE: fila de tácticas (Acceso inicial, Ejecución, Persistencia, Escalamiento de privilegios, Comando y control...) con las técnicas detectadas como tarjetas (ID, nombre, por qué, líneas); las tácticas sin detección quedan apagadas.
f) Playbook: pestañas por fase; cada paso es un checkbox con barra de progreso global; los comandos tienen botón copiar; los pasos con requiere_aprobacion llevan ⚠️ y un aviso visible. Incluye escalamiento y mejoras.
g) Panel "Qué corrigió Opus": correcciones_orquestador y lo que no se puede concluir.
h) Métricas: barras de tokens y tiempo por rol, y totales Opus vs Sonnet.
i) Botón "Modo explicado" que muestra u oculta notas breves (qué es cada sección y por qué importa), para narrar la demo.

ORDEN DE CONSTRUCCIÓN
1) Pasos 1 a 3 y --dry-run. 2) Pasos 4 a 6 con reporte.json. 3) Dashboard con --replay usando un reporte.json real. 4) --serve con SSE. Verifica cada etapa antes de seguir.

CALIDAD
Accesible (contraste, foco con teclado), sin dependencias externas ni errores en consola. README corto, en tono natural, con un diagrama ASCII del flujo orquestador → workers → síntesis y los comandos de uso. Al final, resume qué verificaste.
