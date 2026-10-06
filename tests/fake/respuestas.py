"""Respuestas pregrabadas del paquete falso `anthropic` (datos de DEMOSTRACION).

Son dicts de Python que se serializan con json.dumps. Cumplen los esquemas
descritos en docs/arquitectura.md y todas las referencias L# apuntan a las 35
lineas de ejemplo_auth.log.

Errores sembrados A PROPOSITO en las salidas de los workers (la sintesis los
corrige y los lista en correcciones_orquestador):
  1. linea_tiempo: el acceso exitoso (L15-L16) lleva hora 03:12:40; la real es 03:12:44.
  2. mitre_indicadores: T1021.004 SSH como "Movimiento lateral" para L31
     (en realidad es el mismo host, web01).
Ademas, la sintesis corrige tres detalles plausibles:
  3. linea_tiempo (L17-L19): afirma "sudo sin contraseña" como hecho; es un supuesto.
  4. La rotacion de la contraseña de deploy aparece duplicada entre
     contencion_erradicacion y recuperacion_mejoras.
  5. El respaldo de evidencia no incluye /home/sysbackup, que luego se borra con userdel -r.
"""

import copy

TAREAS = (
    "planificacion",
    "linea_tiempo",
    "mitre_indicadores",
    "contencion_erradicacion",
    "recuperacion_mejoras",
    "sintesis",
)

IP_ATACANTE = "203.0.113.45"
IP_DESCARGA = "198.51.100.23"
HUELLA_L31 = "SHA256:q3Xc8vRk2pLm9TzYw4HnB7dFs1eJuA6oKiG5rN0bVxE"

# ---------------------------------------------------------------------------
# 1. PLANIFICACION (orquestador)
# ---------------------------------------------------------------------------

PLANIFICACION = {
    "clasificacion": {
        "tipo": "Compromiso de cuenta SSH por fuerza bruta con persistencia y escalamiento de privilegios",
        "severidad": "crítica",
        "justificacion": (
            "Desde 203.0.113.45 hay 12 intentos fallidos en 38 segundos contra admin, test, oracle, "
            "root y deploy (L3-L14) que terminan en un login exitoso de deploy a las 03:12:44 (L15). "
            "En poco más de dos minutos esa sesión usa sudo como root (L17-L29): lee /etc/shadow (L19), "
            "crea la cuenta sysbackup y la añade al grupo sudo (L20-L25), le fija contraseña (L26-L27) "
            "y descarga y ejecuta /tmp/.update.sh desde 198.51.100.23 (L28-L29). Después sysbackup "
            "entra por clave pública desde la misma IP atacante (L31). Hay acceso root, persistencia, "
            "ejecución de código no verificado y posible exposición de credenciales; por eso es crítica."
        ),
    },
    "instrucciones": {
        "linea_tiempo": (
            "Construye entre 10 y 12 entradas que cubran todo el log (L1-L35). Agrupa así: fallos por "
            "usuario (L3-L7 usuarios inexistentes admin, test y oracle; L8-L11 root; L12-L14 deploy), el "
            "acceso exitoso de deploy (L15-L16), el uso de sudo como root (L17-L19), la creación de "
            "sysbackup (L20-L22), su alta en sudo (L23-L25), el cambio de contraseña (L26-L27), la "
            "descarga y ejecución de /tmp/.update.sh desde 198.51.100.23 (L28-L30) y el login por clave "
            "pública de sysbackup (L31-L32). Incluye el CRON de L1-L2 como actividad normal y el "
            "contraste de ana desde 10.0.0.25 (L33-L35). Usa la hora de la primera línea de cada rango. "
            "En cada explicación habla como analista senior con un junior: qué significa la línea, por "
            "qué importa y qué mirarías después."
        ),
        "mitre_indicadores": (
            "Mapea a MITRE ATT&CK solo lo que el log respalda, con ID real y líneas exactas: fuerza "
            "bruta (L3-L14), cuenta válida deploy (L15), uso de sudo (L17-L29), lectura de /etc/shadow "
            "(L19), cuenta nueva sysbackup (L20-L22), cambios de grupo y contraseña (L23-L27), descarga "
            "del script (L28) y su ejecución (L29). Lista como indicadores las IPs 203.0.113.45 y "
            "198.51.100.23, la cuenta sysbackup, /tmp/.update.sh, la URL de descarga y la huella de la "
            "clave de L31, cada uno con sus líneas. En no_concluible anota lo que el log no permite "
            "afirmar (contenido y efecto del script, cómo llegó la clave pública de sysbackup, "
            "exfiltración, salida de /etc/shadow). Distingue siempre entre lo observado y lo supuesto."
        ),
        "contencion_erradicacion": (
            "Propón tres fases (Preservar evidencia, Contención y Erradicación) de 3 a 5 pasos cada una, "
            "con comandos Linux defensivos concretos. Primero preserva: auth.log con sha256sum, sesiones "
            "con last -i, conexiones con ss -tnp, procesos con ps auxf y el script /tmp/.update.sh de "
            "L28-L29. Después contén: bloquea 203.0.113.45 y 198.51.100.23, bloquea la cuenta sysbackup "
            "(L22-L25), sácala del grupo sudo y cierra sus sesiones (L32 no tiene línea de cierre). Por "
            "último erradica: revisa ~sysbackup/.ssh/authorized_keys frente a la huella de L31, crontab y "
            "unidades systemd, rota la contraseña de deploy comprometida en L15 y borra el script y la "
            "cuenta. Marca requiere_aprobacion=true en todo paso que corte acceso o borre. No hagas nada "
            "contra las IPs externas salvo bloquearlas."
        ),
        "recuperacion_mejoras": (
            "Propón la fase 'Recuperación y verificación': comprobar que no quedan cuentas, claves SSH, "
            "tareas cron ni servicios extraños tras la cuenta sysbackup (L22-L24); verificar la "
            "integridad de paquetes con debsums o dpkg --verify porque el script de L29 corrió como "
            "root; rotar credenciales porque /etc/shadow se leyó en L19; y reabrir con monitorización. "
            "Añade escalamiento (a quién y cuándo: responsable de seguridad, dueño del sistema, "
            "legal/DPO si /etc/shadow pudo filtrarse; marca 'supuesto' donde dependa de datos que el log "
            "no muestra) y mejoras que habrían impedido o detectado el ataque (L3-L15 sin bloqueo, "
            "L20-L25 sin alerta)."
        ),
    },
}

# ---------------------------------------------------------------------------
# 2. LINEA DE TIEMPO (worker). Contiene el error sembrado de la hora de L15.
# ---------------------------------------------------------------------------

_EXPLICACION_SUDO_WORKER = (
    "Nada más entrar, deploy usa sudo para ejecutar id como root (L17-L18), el clásico 'quién soy y qué "
    "puedo hacer' de quien acaba de conseguir una sesión. A los 18 segundos lee /etc/shadow con cat "
    "(L19), el archivo con los hashes de todas las contraseñas del sistema. Como deploy tiene sudo sin "
    "contraseña (NOPASSWD), el atacante llegó a root sin ningún obstáculo. Lo siguiente que miraría es "
    "si esos hashes salieron del servidor."
)

LINEA_TIEMPO = {
    "linea_tiempo": [
        {
            "lineas": [1, 2],
            "hora": "02:58:01",
            "titulo": "Tarea CRON normal de root (línea base)",
            "explicacion": (
                "Estas dos líneas son una sesión de CRON de root que se abre y se cierra en el mismo "
                "segundo (L1-L2). Es ruido habitual: una tarea programada corriendo, sin una persona "
                "detrás. La anoto como línea base para saber cómo se ve lo normal antes de que empiece "
                "lo raro; después comprobaría que esa tarea figura en el crontab del sistema."
            ),
            "tipo": "otro",
        },
        {
            "lineas": [3, 7],
            "hora": "03:12:01",
            "titulo": "Fuerza bruta contra usuarios inexistentes",
            "explicacion": (
                "Desde 203.0.113.45 llegan cinco intentos seguidos contra admin, test y oracle, cuentas "
                "que ni existen en el servidor (L3-L7, fíjate en 'invalid user'). Probar nombres "
                "genéricos es lo típico de un escáner automático: no sabe quién existe y prueba lo "
                "habitual. El ritmo, un intento cada 3 segundos, delata a un script y no a una persona "
                "tecleando. Lo siguiente que miraría es si esa misma IP prueba cuentas reales."
            ),
            "tipo": "fallo",
        },
        {
            "lineas": [8, 11],
            "hora": "03:12:17",
            "titulo": "Ataque contra root",
            "explicacion": (
                "Ahora el atacante prueba root cuatro veces seguidas (L8-L11). Ya no aparece 'invalid "
                "user', y esa es la señal de que la cuenta sí existe en el servidor. Si PermitRootLogin "
                "estuviera en 'no', aunque acertaran la contraseña no podrían entrar como root, así que "
                "revisaría esa opción en sshd_config. También me preguntaría por qué nadie bloqueó la "
                "IP tras tantos fallos."
            ),
            "tipo": "fallo",
        },
        {
            "lineas": [12, 14],
            "hora": "03:12:31",
            "titulo": "Ataque contra deploy, una cuenta real",
            "explicacion": (
                "El último blanco es deploy (L12-L14), otra cuenta real: otra vez sin 'invalid user'. "
                "Que el atacante pase de nombres genéricos a deploy sugiere que ya sabía o dedujo que "
                "existía, aunque el log no lo prueba (supuesto). Tras tres fallos viene el éxito en la "
                "línea siguiente, así que mira L15 con lupa."
            ),
            "tipo": "fallo",
        },
        {
            "lineas": [15, 16],
            "hora": "03:12:40",  # ERROR SEMBRADO: la hora real en L15 es 03:12:44
            "titulo": "Login exitoso de deploy desde la IP atacante",
            "explicacion": (
                "En L15 aparece 'Accepted password for deploy' desde 203.0.113.45, la misma IP que "
                "acababa de fallar 12 veces: casi con seguridad es el atacante entrando, no un usuario "
                "que recordó su contraseña. L16 confirma que se abrió la sesión (uid=1001). Este es el "
                "momento en que un intento de intrusión pasa a ser un incidente confirmado. Lo "
                "siguiente que miraría es todo lo que hizo esa sesión desde L17."
            ),
            "tipo": "acceso",
        },
        {
            "lineas": [17, 19],
            "hora": "03:13:02",
            "titulo": "Primeros comandos con sudo: id y lectura de /etc/shadow",
            "explicacion": _EXPLICACION_SUDO_WORKER,
            "tipo": "sudo",
        },
        {
            "lineas": [20, 22],
            "hora": "03:13:41",
            "titulo": "Se crea la cuenta sysbackup",
            "explicacion": (
                "Con sudo, deploy ejecuta useradd -m -s /bin/bash sysbackup (L20) y useradd registra el "
                "grupo y el usuario nuevos (L21-L22): UID 1002, shell bash y directorio propio. El "
                "nombre parece elegido para pasar por una cuenta de sistema legítima, un truco de "
                "camuflaje habitual. Es persistencia: aunque cambies la contraseña de deploy, el "
                "atacante conserva una puerta. Lo siguiente es preguntar al equipo si alguien conoce a "
                "sysbackup; si nadie, es del atacante."
            ),
            "tipo": "cuenta_nueva",
        },
        {
            "lineas": [23, 25],
            "hora": "03:13:58",
            "titulo": "sysbackup entra al grupo sudo",
            "explicacion": (
                "En L23-L24 se ejecuta usermod -aG sudo sysbackup y se registra el alta en el grupo "
                "sudo. L25 repite lo mismo para el grupo en gshadow, no es una acción nueva. El "
                "atacante se asegura de que su cuenta tenga privilegios de administrador: escalamiento "
                "y persistencia a la vez. Yo revisaría también /etc/sudoers.d por si dejó algo más."
            ),
            "tipo": "grupo",
        },
        {
            "lineas": [26, 27],
            "hora": "03:14:15",
            "titulo": "Contraseña de sysbackup establecida",
            "explicacion": (
                "L26 muestra a deploy lanzando passwd sysbackup con sudo y L27 confirma 'password "
                "changed for sysbackup'. Con contraseña y pertenencia a sudo, sysbackup ya es una cuenta "
                "de administrador plenamente funcional. El log no guarda la contraseña (ni debe), así "
                "que hay que asumir que la conoce el atacante. Lo siguiente es verificar que esa cuenta "
                "no pueda volver a entrar."
            ),
            "tipo": "password",
        },
        {
            "lineas": [28, 30],
            "hora": "03:14:50",
            "titulo": "Descarga y ejecución de /tmp/.update.sh desde 198.51.100.23",
            "explicacion": (
                "En L28 deploy descarga con wget un update.sh desde 198.51.100.23 y lo guarda como "
                "/tmp/.update.sh; el punto inicial lo esconde de un ls normal. Doce segundos después, "
                "en L29, lo ejecuta con bash como root, y en L30 la sesión de deploy se cierra. No "
                "sabemos qué hacía el script porque el log solo registra que se ejecutó. Lo primero "
                "que haría es copiar ese archivo como evidencia antes de que alguien lo borre."
            ),
            "tipo": "descarga",
        },
        {
            "lineas": [31, 32],
            "hora": "03:21:07",
            "titulo": "Reacceso de sysbackup por clave pública",
            "explicacion": (
                "Poco más de cinco minutos después de cerrarse la sesión de deploy (L30) aparece "
                "'Accepted publickey for sysbackup' desde 203.0.113.45 con una clave RSA (L31) y se "
                "abre la sesión (L32). Es la prueba de persistencia: ya no necesita la contraseña de "
                "deploy y entra con clave. Lo que más me preocupa es que no vemos cómo se instaló esa "
                "clave; eso se averigua en el disco. Tampoco hay línea de cierre, así que la sesión "
                "podría seguir abierta."
            ),
            "tipo": "acceso",
        },
        {
            "lineas": [33, 35],
            "hora": "08:02:15",
            "titulo": "Login normal de ana desde la red interna (contraste)",
            "explicacion": (
                "A las 08:02 entra ana por clave pública desde 10.0.0.25, una IP interna (L33-L34), y "
                "a las 08:03 ejecuta apt update con sudo (L35). Es comportamiento normal: horario "
                "laboral, red interna, clave ED25519 y un comando rutinario. Compáralo con el bloque de "
                "las 03:12: otra hora, IP externa, contraseña adivinada y comandos de reconocimiento y "
                "persistencia. Esa comparación es lo que enseña a distinguir ruido de ataque."
            ),
            "tipo": "acceso",
        },
    ]
}

# ---------------------------------------------------------------------------
# 3. MITRE + INDICADORES (worker). Contiene T1021.004 como error sembrado.
# ---------------------------------------------------------------------------

_POR_QUE_T1078_WORKER = (
    "El atacante entra en L15 con la contraseña real de la cuenta local deploy: no explotó ninguna "
    "vulnerabilidad, usó credenciales válidas, por eso el acceso parece legítimo en el log. Es acceso "
    "inicial y también un punto de apoyo mientras la contraseña siga siendo válida. La cuenta creada "
    "después (sysbackup) se reutiliza para reentrar en L31."
)

_T1021_SEMBRADO = {
    "id": "T1021.004",
    "nombre": "Servicios remotos: SSH",
    "tactica": "Movimiento lateral",
    "lineas": "L31",
    "por_que": (
        "El login por clave pública de sysbackup desde 203.0.113.45 (L31) es una conexión SSH remota, "
        "es decir, el uso de servicios remotos para moverse lateralmente por la red del objetivo."
    ),
}

MITRE_INDICADORES = {
    "mitre": [
        {
            "id": "T1110.001",
            "nombre": "Fuerza bruta: adivinación de contraseñas",
            "tactica": "Acceso a credenciales",
            "lineas": "L3-L14",
            "por_que": (
                "Doce intentos fallidos en 38 segundos desde 203.0.113.45 contra admin, test, oracle, "
                "root y deploy (L3-L14), con un ritmo regular de pocos segundos entre intentos que "
                "apunta a una herramienta automática. Terminan en el login exitoso de L15."
            ),
        },
        {
            "id": "T1078.003",
            "nombre": "Cuentas válidas: cuentas locales",
            "tactica": "Acceso inicial, Persistencia",
            "lineas": "L15",
            "por_que": _POR_QUE_T1078_WORKER,
        },
        {
            "id": "T1548.003",
            "nombre": "Abuso de mecanismos de elevación: sudo y caché de sudo",
            "tactica": "Escalamiento de privilegios",
            "lineas": "L17-L29",
            "por_que": (
                "Toda la actividad de la sesión de deploy pasa por sudo como root: id (L17), "
                "cat /etc/shadow (L19), useradd (L20), usermod (L23), passwd (L26), wget (L28) y bash "
                "(L29). El atacante abusa del permiso sudo legítimo de deploy para actuar con "
                "privilegios máximos. El log no muestra si sudo pidió contraseña ni cómo está "
                "configurado sudoers."
            ),
        },
        {
            "id": "T1003.008",
            "nombre": "Volcado de credenciales del SO: /etc/passwd y /etc/shadow",
            "tactica": "Acceso a credenciales",
            "lineas": "L19",
            "por_que": (
                "Con sudo cat /etc/shadow (L19) se lee el archivo con los hashes de contraseñas de "
                "todas las cuentas locales. Es el paso previo a descifrarlos fuera del servidor o a "
                "reutilizarlos. Debe tratarse como exposición de credenciales aunque no sepamos si "
                "salieron del equipo."
            ),
        },
        {
            "id": "T1136.001",
            "nombre": "Crear cuenta: cuenta local",
            "tactica": "Persistencia",
            "lineas": "L20-L22",
            "por_que": (
                "useradd -m -s /bin/bash sysbackup (L20) crea una cuenta local nueva con UID 1002 y "
                "directorio propio (L21-L22). Su nombre imita una cuenta de sistema legítima y le da al "
                "atacante una puerta que sobrevive al cambio de contraseña de deploy."
            ),
        },
        {
            "id": "T1098",
            "nombre": "Manipulación de cuentas",
            "tactica": "Persistencia, Escalamiento de privilegios",
            "lineas": "L23-L27",
            "por_que": (
                "El atacante modifica la cuenta nueva para hacerla útil: la añade al grupo sudo "
                "(L23-L25) y le fija contraseña (L26-L27). Así sysbackup es administradora completa. "
                "Es persistencia y escalamiento al mismo tiempo."
            ),
        },
        {
            "id": "T1105",
            "nombre": "Transferencia de herramientas de entrada",
            "tactica": "Comando y control",
            "lineas": "L28",
            "por_que": (
                "wget descarga update.sh desde 198.51.100.23 y lo guarda oculto como /tmp/.update.sh "
                "(L28). Es la transferencia de una herramienta externa al servidor comprometido."
            ),
        },
        {
            "id": "T1059.004",
            "nombre": "Intérprete de comandos y scripts: shell de Unix",
            "tactica": "Ejecución",
            "lineas": "L29",
            "por_que": (
                "bash /tmp/.update.sh ejecutado como root (L29) es la ejecución de un script con el "
                "intérprete de shell de Unix. No sabemos qué contiene (ver no_concluible)."
            ),
        },
        _T1021_SEMBRADO,
    ],
    "indicadores": [
        {
            "texto": "IP atacante 203.0.113.45: origen de los 12 intentos fallidos y del login exitoso de deploy",
            "lineas": "L3-L15",
        },
        {
            "texto": "Cuenta comprometida: deploy (su contraseña acabó en manos del atacante tras la fuerza bruta)",
            "lineas": "L12-L15",
        },
        {
            "texto": "Cuenta creada por el atacante: sysbackup (UID 1002, shell /bin/bash, miembro del grupo sudo)",
            "lineas": "L22-L24",
        },
        {
            "texto": "IP 198.51.100.23: servidor desde el que se descargó el script con wget",
            "lineas": "L28",
        },
        {
            "texto": "URL de descarga: http://198.51.100.23/update.sh",
            "lineas": "L28",
        },
        {
            "texto": "Archivo /tmp/.update.sh (oculto por el punto inicial), descargado y ejecutado como root con bash",
            "lineas": "L28-L29",
        },
        {
            "texto": (
                "Huella de la clave pública con la que sysbackup entró desde 203.0.113.45: RSA "
                + HUELLA_L31
            ),
            "lineas": "L31",
        },
        {
            "texto": "Lectura de /etc/shadow con sudo cat (hashes de contraseñas potencialmente expuestos)",
            "lineas": "L19",
        },
    ],
    "no_concluible": [
        (
            "Qué hizo /tmp/.update.sh al ejecutarse como root (L29): el log solo registra la ejecución, "
            "no el contenido del script ni sus efectos. Hace falta la copia del archivo para analizarlo."
        ),
        (
            "Cómo se instaló la clave pública con la que sysbackup entró en L31: ninguna línea muestra "
            "la escritura de ~sysbackup/.ssh/authorized_keys. Supuesto: la dejó el script de L29, pero "
            "hay que comprobarlo en el disco."
        ),
        (
            "Si hubo exfiltración de datos: auth.log no registra tráfico de red ni transferencias de "
            "archivos, así que no se puede afirmar ni descartar tras L19 y L28-L29."
        ),
        (
            "Si el contenido de /etc/shadow salió del servidor: L19 muestra que se leyó con cat en la "
            "terminal pts/0 de la sesión del atacante, por lo que hay que asumir que vio los hashes; lo "
            "que el log no dice es si los copió fuera o los descifró."
        ),
        (
            "Qué hizo sysbackup en su sesión de L31-L32: el log termina sin comandos suyos (ni sudo) y "
            "sin línea de cierre de esa sesión, así que podría seguir abierta."
        ),
    ],
}

# ---------------------------------------------------------------------------
# 4. CONTENCION Y ERRADICACION (worker)
# ---------------------------------------------------------------------------

_CMD_RESPALDO_CUENTAS_WORKER = (
    "sudo tar czpf /root/evidencia_IR/cuentas_y_persistencia.tgz /etc/passwd /etc/group /etc/sudoers "
    "/etc/sudoers.d /var/spool/cron /etc/cron.d /etc/systemd/system; "
    "sudo sh -c 'cd /root/evidencia_IR && sha256sum cuentas_y_persistencia.tgz >> SHA256SUMS'"
)

_TEXTO_RESPALDO_CUENTAS_WORKER = (
    "Respalda los archivos de cuentas y de persistencia en su estado actual para poder compararlos "
    "después (cuentas de L20-L27, cron y unidades systemd). Luego copia toda la carpeta de evidencia "
    "fuera del servidor, por ejemplo con scp a tu estación forense (supuesto: existe una)."
)

_PASOS_PRESERVAR_BASE = [
    {
        "texto": (
            "Antes de tocar nada, crea una carpeta de evidencia con permisos restringidos, copia los logs "
            "de autenticación (donde están L1-L35) y calcula su hash SHA-256 para poder demostrar "
            "después que no se alteraron."
        ),
        "comando": (
            "sudo install -d -m 700 /root/evidencia_IR && sudo cp -p /var/log/auth.log* /root/evidencia_IR/ "
            "&& sudo sh -c 'cd /root/evidencia_IR && sha256sum auth.log* > SHA256SUMS && cat SHA256SUMS'"
        ),
        "requiere_aprobacion": False,
    },
    {
        "texto": (
            "Registra quién está conectado y los accesos recientes con su IP de origen. L32 abrió una "
            "sesión de sysbackup sin línea de cierre, así que puede seguir viva."
        ),
        "comando": "(who -a; echo '--- last -i ---'; last -i -n 50) | sudo tee /root/evidencia_IR/sesiones.txt",
        "requiere_aprobacion": False,
    },
    {
        "texto": (
            "Captura las conexiones de red y el árbol de procesos antes de bloquear nada: es evidencia "
            "volátil que se pierde al cortar sesiones o reiniciar. No reinicies el servidor."
        ),
        "comando": "(sudo ss -tnp; echo '--- ps auxf ---'; ps auxf) | sudo tee /root/evidencia_IR/red_y_procesos.txt",
        "requiere_aprobacion": False,
    },
    {
        "texto": (
            "Copia el script descargado en L28 y ejecutado en L29 a la carpeta de evidencia sin "
            "ejecutarlo, con permisos 600 y su hash, antes de borrar nada."
        ),
        "comando": (
            "sudo cp -p /tmp/.update.sh /root/evidencia_IR/update.sh.muestra && sudo chmod 600 "
            "/root/evidencia_IR/update.sh.muestra && sudo sh -c 'sha256sum /tmp/.update.sh "
            "/root/evidencia_IR/update.sh.muestra > /root/evidencia_IR/update.sh.sha256 && cat "
            "/root/evidencia_IR/update.sh.sha256' && sudo stat /tmp/.update.sh"
        ),
        "requiere_aprobacion": False,
    },
]

_PASOS_CONTENCION = [
    {
        "texto": (
            "Bloquea en el firewall las dos IPs del incidente: 203.0.113.45 (origen del ataque, L3-L15 "
            "y L31) y 198.51.100.23 (origen de la descarga, L28), esta última también en salida. Insertar "
            "la regla en primera posición corta además las sesiones ya establecidas desde 203.0.113.45. "
            "Supuesto: el host usa iptables; con nftables la regla equivalente sería "
            "'nft add rule inet filter input ip saddr 203.0.113.45 drop' (supuesto: existen la tabla "
            "inet filter y la cadena input)."
        ),
        "comando": (
            "sudo iptables -I INPUT 1 -s 203.0.113.45 -j DROP && sudo iptables -I INPUT 1 -s "
            "198.51.100.23 -j DROP && sudo iptables -I OUTPUT 1 -d 198.51.100.23 -j DROP"
        ),
        "requiere_aprobacion": True,
    },
    {
        "texto": (
            "Bloquea la cuenta sysbackup (creada en L20-L22): contraseña bloqueada, cuenta caducada y "
            "shell nologin. Con solo usermod -L (o passwd -l) el acceso por clave pública de L31 podría "
            "seguir funcionando, por eso se caduca la cuenta también."
        ),
        "comando": "sudo usermod -L -e 1 -s /usr/sbin/nologin sysbackup",
        "requiere_aprobacion": True,
    },
    {
        "texto": (
            "Retira sysbackup del grupo sudo (alta en L23-L24) para que, aunque lograra entrar, no "
            "pueda actuar como root."
        ),
        "comando": "sudo gpasswd -d sysbackup sudo",
        "requiere_aprobacion": True,
    },
    {
        "texto": (
            "Cierra todas las sesiones y procesos de sysbackup (L32 abrió una sesión sin cierre en el "
            "log). Hazlo después de bloquear la cuenta y de haber preservado la evidencia volátil."
        ),
        "comando": "sudo pkill -KILL -u sysbackup",
        "requiere_aprobacion": True,
    },
    {
        "texto": (
            "Verifica que la contención funciona: no deben quedar conexiones con las IPs bloqueadas ni "
            "sesiones de sysbackup."
        ),
        "comando": (
            "sudo ss -tnp | grep -F -e 203.0.113.45 -e 198.51.100.23 || echo 'Sin conexiones con las "
            "IPs bloqueadas'; who | grep sysbackup || echo 'Sin sesiones de sysbackup'"
        ),
        "requiere_aprobacion": False,
    },
]

_PASOS_ERRADICACION = [
    {
        "texto": (
            "Compara las claves públicas autorizadas con la huella de L31 (" + HUELLA_L31 + ") para "
            "saber qué clave usó sysbackup, y revisa también las de deploy y root por si el atacante "
            "dejó claves allí."
        ),
        "comando": (
            "sudo sh -c 'for f in /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys; do [ -f \"$f\" ] "
            "&& echo \"== $f\" && ssh-keygen -lf \"$f\"; done'"
        ),
        "requiere_aprobacion": False,
    },
    {
        "texto": (
            "Busca persistencia adicional: crontabs de usuarios, tareas en /etc/cron.* y servicios o "
            "temporizadores systemd modificados en los últimos días (el script de L29 corrió como root "
            "y podría haber instalado cualquier cosa)."
        ),
        "comando": (
            "sudo sh -c 'ls -l /var/spool/cron/crontabs /etc/cron.d; find /etc/systemd/system /etc/cron.d "
            "/etc/cron.daily /var/spool/cron -mtime -3 -ls; systemctl list-unit-files --state=enabled "
            "--no-pager'"
        ),
        "requiere_aprobacion": False,
    },
    {
        "texto": (
            "Rota la contraseña de deploy, que el atacante obtuvo en L15, y fuerza su cambio en el "
            "siguiente inicio de sesión. Coordina con su dueño porque cortará su acceso actual "
            "(supuesto: es una cuenta de servicio compartida)."
        ),
        "comando": "sudo passwd deploy && sudo chage -d 0 deploy",
        "requiere_aprobacion": True,
    },
    {
        "texto": (
            "Antes de borrar, inventaría lo que pertenece a sysbackup y los archivos ocultos de /tmp "
            "para no dejar restos del atacante."
        ),
        "comando": r"sudo find / -xdev \( -user sysbackup -o -path '/tmp/.*' \) -ls 2>/dev/null",
        "requiere_aprobacion": False,
    },
    {
        "texto": (
            "Solo cuando hayas verificado los hashes y la copia de la evidencia, borra el script de "
            "L28-L29 y elimina la cuenta sysbackup junto con su directorio personal."
        ),
        "comando": "sudo rm -f -- /tmp/.update.sh && sudo userdel -r sysbackup",
        "requiere_aprobacion": True,
    },
]


def _pasos_preservar(con_home_sysbackup: bool) -> list:
    """Pasos de 'Preservar evidencia'; el 5.º varía entre worker y síntesis."""
    pasos = copy.deepcopy(_PASOS_PRESERVAR_BASE)
    if con_home_sysbackup:
        texto = (
            "Respalda los archivos de cuentas y de persistencia en su estado actual, incluido el "
            "directorio personal de sysbackup con su authorized_keys (la prueba de cómo entró en L31), "
            "para compararlos después y antes de cualquier borrado (cuentas de L20-L27, cron y "
            "unidades systemd). Luego copia toda la carpeta de evidencia fuera del servidor, por ejemplo "
            "con scp a tu estación forense (supuesto: existe una)."
        )
        comando = _CMD_RESPALDO_CUENTAS_WORKER.replace(
            "/etc/sudoers.d /var/spool/cron", "/etc/sudoers.d /home/sysbackup /var/spool/cron"
        )
    else:
        texto = _TEXTO_RESPALDO_CUENTAS_WORKER
        comando = _CMD_RESPALDO_CUENTAS_WORKER
    pasos.append({"texto": texto, "comando": comando, "requiere_aprobacion": False})
    return pasos


CONTENCION_ERRADICACION = {
    "fases": [
        {"nombre": "Preservar evidencia", "pasos": _pasos_preservar(False)},
        {"nombre": "Contención", "pasos": copy.deepcopy(_PASOS_CONTENCION)},
        {"nombre": "Erradicación", "pasos": copy.deepcopy(_PASOS_ERRADICACION)},
    ]
}

# ---------------------------------------------------------------------------
# 5. RECUPERACION Y MEJORAS (worker). Rota deploy otra vez (duplicado sembrado).
# ---------------------------------------------------------------------------

_PASOS_RECUPERACION_BASE = [
    {
        "texto": (
            "Verifica que solo existen las cuentas esperadas: ninguna con UID 0 aparte de root, "
            "sysbackup (L22) ya no está y el grupo sudo contiene solo a quien debe."
        ),
        "comando": "awk -F: '$3==0 || $3>=1000 {print $1, $3, $6, $7}' /etc/passwd; getent group sudo",
        "requiere_aprobacion": False,
    },
    {
        "texto": (
            "Confirma que no quedan claves SSH, tareas cron ni servicios extraños: la salida debe "
            "coincidir con tu inventario y no mostrar nada nuevo desde el momento de L20."
        ),
        "comando": (
            "sudo sh -c 'ls -l /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null; "
            "ls -l /var/spool/cron/crontabs /etc/cron.d; systemctl list-units --type=service "
            "--state=running --no-pager; ss -tlnp'"
        ),
        "requiere_aprobacion": False,
    },
    {
        "texto": (
            "Comprueba la integridad de los paquetes instalados, porque el script de L29 corrió como "
            "root. Si aparecen binarios del sistema modificados (sshd, sudo, bash), lo prudente es "
            "reconstruir el servidor (supuesto)."
        ),
        "comando": "if command -v debsums >/dev/null; then sudo debsums -s; else sudo dpkg --verify; fi",
        "requiere_aprobacion": False,
    },
]

_PASO_ROTAR_WORKER = {
    "texto": (
        "Rota las credenciales: restablece la contraseña de deploy (comprometida en L15) y obliga al "
        "resto de usuarios locales a cambiar la suya, porque /etc/shadow se leyó en L19. Rota también "
        "claves y tokens que estén guardados en el servidor (supuesto: existen)."
    ),
    "comando": (
        "sudo passwd deploy; for u in $(awk -F: '$3>=1000 && $1!=\"nobody\" {print $1}' /etc/passwd); "
        "do sudo chage -d 0 \"$u\"; done"
    ),
    "requiere_aprobacion": True,
}

_PASO_ROTAR_SINTESIS = {
    "texto": (
        "Obliga al resto de usuarios locales a cambiar su contraseña en el siguiente inicio de sesión, "
        "porque /etc/shadow se leyó en L19 (deploy ya se rotó en Erradicación). Rota también claves y "
        "tokens que estén guardados en el servidor (supuesto: existen)."
    ),
    "comando": (
        "for u in $(awk -F: '$3>=1000 && $1!=\"nobody\" && $1!=\"deploy\" {print $1}' /etc/passwd); "
        "do sudo chage -d 0 \"$u\"; done"
    ),
    "requiere_aprobacion": True,
}

_PASO_REABRIR = {
    "texto": (
        "Reabre el servicio con el visto bueno del dueño del sistema, manteniendo bloqueadas "
        "203.0.113.45 y 198.51.100.23, y vigila en tiempo real durante unos días (supuesto: 72 horas) "
        "los fallos, accesos, sudo y altas de cuentas, justo lo que no se vigilaba en L3-L29."
    ),
    "comando": (
        "sudo tail -F /var/log/auth.log | grep --line-buffered -E "
        "'Failed password|Accepted|sudo:|useradd|usermod|passwd'"
    ),
    "requiere_aprobacion": False,
}

_ESCALAMIENTO = [
    (
        "Responsable de seguridad o jefe del SOC: de inmediato, antes de ejecutar el playbook. Hay acceso "
        "como root (L17-L29), una cuenta de administrador creada por el atacante (L20-L25) y ejecución "
        "de un script externo (L29)."
    ),
    (
        "Dueño del sistema web01 e infraestructura: de inmediato, para aprobar el bloqueo de las IPs, "
        "el cierre de sesiones y el borrado de la cuenta, y para decidir si el servidor se aísla o se "
        "reconstruye (supuesto: si los paquetes no pasan la verificación o aparecen persistencias sin "
        "explicar)."
    ),
    (
        "Responsable de la cuenta deploy: al rotar su contraseña, para confirmar que no reconoce el "
        "acceso de L15 y reemitir credenciales."
    ),
    (
        "Legal y delegado de protección de datos (DPO): supuesto, solo si web01 guarda datos personales. "
        "Se leyó /etc/shadow (L19) y no se puede descartar que saliera del servidor, así que conviene "
        "avisarles ya para que valoren si hay obligación de notificar y en qué plazo."
    ),
    (
        "Equipo de red o proveedor de hosting: supuesto, pedir el bloqueo en el perímetro de "
        "203.0.113.45 y 198.51.100.23 y los registros de tráfico saliente de web01 desde las 03:12 "
        "(L15), para saber si hubo exfiltración."
    ),
    (
        "Respuesta a incidentes externa o CSIRT: supuesto, solo si se confirma exfiltración o "
        "movimiento hacia otros equipos."
    ),
]

_MEJORAS = [
    (
        "Desactivar PasswordAuthentication en /etc/ssh/sshd_config y exigir clave pública: el atacante "
        "entró adivinando una contraseña (L3-L15)."
    ),
    "Poner PermitRootLogin no: root fue uno de los usuarios atacados (L8-L11).",
    (
        "Instalar fail2ban (o equivalente) para banear una IP tras pocos fallos: aquí hubo 12 intentos "
        "en 38 segundos (L3-L14) sin ninguna reacción."
    ),
    "Exigir MFA (por ejemplo una llave FIDO2 o TOTP con PAM) para el acceso SSH y para sudo.",
    (
        "Restringir quién puede entrar por SSH con AllowUsers o AllowGroups y, si es posible, limitar el "
        "origen a rangos de confianza."
    ),
    (
        "Alertar en el SIEM o con auditd sobre altas de cuentas y de miembros del grupo sudo (useradd y "
        "usermod, L20-L25) y sobre sudo fuera de horario (L17-L29)."
    ),
    (
        "Revisar el sudoers de deploy con sudo -l -U deploy y aplicar mínimo privilegio, evitando "
        "NOPASSWD si lo tuviera (supuesto: el log no lo confirma)."
    ),
    (
        "Filtrar el tráfico saliente del servidor (egress) para que web01 no pueda descargar de IPs "
        "arbitrarias como en L28."
    ),
    "Enviar los logs de autenticación a un servidor central para que un atacante con root no pueda alterarlos.",
]

RECUPERACION_MEJORAS = {
    "fases": [
        {
            "nombre": "Recuperación y verificación",
            "pasos": copy.deepcopy(_PASOS_RECUPERACION_BASE)
            + [copy.deepcopy(_PASO_ROTAR_WORKER), copy.deepcopy(_PASO_REABRIR)],
        }
    ],
    "escalamiento": list(_ESCALAMIENTO),
    "mejoras": list(_MEJORAS),
}

# ---------------------------------------------------------------------------
# 6. SINTESIS (orquestador): corrige los errores sembrados y completa huecos.
# ---------------------------------------------------------------------------

_EXPLICACION_SUDO_SINTESIS = (
    "Nada más entrar, deploy usa sudo para ejecutar id como root (L17-L18), el clásico 'quién soy y qué "
    "puedo hacer' de quien acaba de conseguir una sesión. A los 18 segundos lee /etc/shadow con cat "
    "(L19), el archivo con los hashes de todas las contraseñas del sistema, así que hay que tratarlo "
    "como una exposición de credenciales. El log no muestra si sudo pidió contraseña: que deploy tenga "
    "sudo sin contraseña (NOPASSWD) es un supuesto que se comprueba con sudo -l -U deploy."
)

_POR_QUE_T1078_SINTESIS = (
    "El atacante entra en L15 con la contraseña real de la cuenta local deploy: no explotó ninguna "
    "vulnerabilidad, usó credenciales válidas, por eso el acceso parece legítimo en el log. Lo mismo "
    "ocurre en L31: sysbackup reentra desde la misma IP externa 203.0.113.45 al mismo host web01, lo "
    "que es reutilizar una cuenta válida y no movimiento lateral."
)

_NO_CONCLUIBLE_LATERAL = (
    "Si hubo movimiento lateral hacia otros equipos: este log es solo de web01 y L31 entra a este mismo "
    "host. No hay evidencia de un segundo equipo, pero con este archivo tampoco se puede descartar."
)

_CORRECCIONES = [
    (
        "Línea de tiempo, L15-L16: linea_tiempo fechaba el acceso exitoso de deploy a las 03:12:40; L15 "
        "registra 'Accepted password for deploy' a las 03:12:44 (L16 también marca 03:12:44). Se corrigió "
        "la hora a 03:12:44."
    ),
    (
        "MITRE, L31: se eliminó T1021.004 (Servicios remotos: SSH) como 'Movimiento lateral'. L31 es un "
        "login por clave pública de sysbackup al mismo host web01 desde 203.0.113.45, la misma IP del "
        "ataque inicial (L3-L15); el log no muestra ningún segundo equipo, así que la afirmación no está "
        "respaldada. El reacceso queda cubierto por T1078.003 y se añadió a no_concluible que no se puede "
        "afirmar ni descartar movimiento hacia otros equipos."
    ),
    (
        "Línea de tiempo, L17-L19: linea_tiempo afirmaba que deploy tiene sudo sin contraseña (NOPASSWD). "
        "L17 solo muestra que sudo ejecutó id como root, no si pidió contraseña ni cómo está configurado "
        "sudoers. Se reescribió como supuesto, verificable con sudo -l -U deploy."
    ),
    (
        "Playbook, rotación de deploy (L15): contencion_erradicacion (Erradicación) y recuperacion_mejoras "
        "(Recuperación) rotaban ambos la contraseña de deploy. Se unificó: queda solo en Erradicación y el "
        "paso de Recuperación se limita al resto de cuentas locales por la lectura de /etc/shadow en L19."
    ),
    (
        "Playbook, Preservar evidencia (L31): el worker borraba sysbackup con userdel -r sin haber "
        "copiado antes su directorio personal, donde vive ~sysbackup/.ssh/authorized_keys, la prueba de "
        "cómo se autenticó en L31. Se añadió /home/sysbackup al respaldo previo a cualquier borrado."
    ),
]


def _construir_sintesis() -> dict:
    linea_tiempo = copy.deepcopy(LINEA_TIEMPO["linea_tiempo"])
    for entrada in linea_tiempo:
        if entrada["lineas"] == [15, 16]:
            entrada["hora"] = "03:12:44"
        elif entrada["lineas"] == [17, 19]:
            entrada["explicacion"] = _EXPLICACION_SUDO_SINTESIS

    mitre = []
    for tecnica in MITRE_INDICADORES["mitre"]:
        if tecnica["id"] == "T1021.004":
            continue
        tecnica = copy.deepcopy(tecnica)
        if tecnica["id"] == "T1078.003":
            tecnica["por_que"] = _POR_QUE_T1078_SINTESIS
        mitre.append(tecnica)

    recuperacion = copy.deepcopy(RECUPERACION_MEJORAS["fases"][0])
    recuperacion["pasos"] = [
        copy.deepcopy(_PASO_ROTAR_SINTESIS) if "passwd deploy" in paso["comando"] else paso
        for paso in recuperacion["pasos"]
    ]

    return {
        "clasificacion": copy.deepcopy(PLANIFICACION["clasificacion"]),
        "linea_tiempo": linea_tiempo,
        "mitre": mitre,
        "indicadores": copy.deepcopy(MITRE_INDICADORES["indicadores"]),
        "no_concluible": copy.deepcopy(MITRE_INDICADORES["no_concluible"]) + [_NO_CONCLUIBLE_LATERAL],
        "playbook": {
            "fases": [
                {"nombre": "Preservar evidencia", "pasos": _pasos_preservar(True)},
                {"nombre": "Contención", "pasos": copy.deepcopy(_PASOS_CONTENCION)},
                {"nombre": "Erradicación", "pasos": copy.deepcopy(_PASOS_ERRADICACION)},
                recuperacion,
            ]
        },
        "escalamiento": list(_ESCALAMIENTO),
        "mejoras": list(_MEJORAS),
        "correcciones_orquestador": list(_CORRECCIONES),
    }


SINTESIS = _construir_sintesis()

RESPUESTAS = {
    "planificacion": PLANIFICACION,
    "linea_tiempo": LINEA_TIEMPO,
    "mitre_indicadores": MITRE_INDICADORES,
    "contencion_erradicacion": CONTENCION_ERRADICACION,
    "recuperacion_mejoras": RECUPERACION_MEJORAS,
    "sintesis": SINTESIS,
}
