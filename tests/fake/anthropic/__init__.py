"""Paquete FALSO `anthropic` para probar SOC Tutor sin API key ni red.

Imita solo la interfaz que usa la herramienta:

    client = anthropic.Anthropic()
    with client.messages.stream(model=..., max_tokens=..., system=..., messages=[...]) as s:
        msg = s.get_final_message()
    msg.content[0].text, msg.usage.input_tokens, msg.usage.output_tokens

(`client.messages.create(...)` devuelve el mismo mensaje directamente.)

Enrutado: la primera línea del prompt de usuario debe ser `TAREA: <nombre>`.
Variables de entorno (se leen en cada llamada):
  FAKE_ESCENARIO  normal (por defecto) | reintento | falla_worker | falla_sintesis
  FAKE_DEMORA     factor de la demora simulada (por defecto 1; 0 = sin dormir)

Las respuestas pregrabadas viven en tests/fake/respuestas.py (datos de demostración).

Uso manual, desde la raíz del repo (PowerShell: `$env:PYTHONPATH = "tests/fake"`):
  PYTHONPATH=tests/fake ANTHROPIC_API_KEY=falsa FAKE_DEMORA=0 python soc_tutor.py ejemplo_auth.log
"""

import json
import os
import random
import re
import sys
import threading
import time

# respuestas.py vive en el directorio padre (tests/fake/); basta con que esa carpeta esté en sys.path,
# pero por robustez lo añadimos al final si no está.
_PADRE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PADRE not in sys.path:
    sys.path.append(_PADRE)

import respuestas  # noqa: E402

__version__ = "0.0.0+fake"
__fake__ = True

TAREAS = respuestas.TAREAS
ESCENARIOS = ("normal", "reintento", "falla_worker", "falla_sintesis")

_TAREAS_LENTAS = {"planificacion": 1.5, "sintesis": 1.5}
_DEMORA_MIN, _DEMORA_MAX = 0.8, 2.5

_TEXTO_NO_JSON = (
    "Claro, aquí tienes el análisis MITRE ATT&CK y los indicadores del incidente. Primero describo las "
    "técnicas (fuerza bruta en L3-L14, uso de sudo en L17-L29) y después los indicadores. Dime si "
    "quieres que lo profundice."
)
_JSON_INVALIDO_CONTENCION = (
    "Este es el plan de contención y erradicación: {fases: [Preservar evidencia, Contención, "
    "Erradicación]} (el detalle de cada paso va a continuación)."
)
_JSON_INVALIDO_SINTESIS = (
    '{"clasificacion": {"tipo": "Compromiso de cuenta SSH por fuerza bruta con persistencia", '
    '"severidad": "crítica", "justificacion": "Desde 203.0.113.45 hay 12 intentos fallidos en 38 segun'
)

_LOCK = threading.Lock()
_CONTADORES = {}
_REGISTRO = []


# --------------------------------------------------------------------------- errores
class APIError(Exception):
    """Base de los errores de la API falsa (existe para que `except anthropic.APIError` funcione)."""


class APIConnectionError(APIError):
    pass


class APIStatusError(APIError):
    pass


class AuthenticationError(APIStatusError):
    pass


class RateLimitError(APIStatusError):
    pass


# --------------------------------------------------------------------------- mensaje
class _BloqueTexto:
    type = "text"

    def __init__(self, text: str) -> None:
        self.text = text


class _Uso:
    def __init__(self, input_tokens: int, output_tokens: int) -> None:
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class _Mensaje:
    type = "message"
    role = "assistant"
    stop_reason = "end_turn"
    stop_sequence = None

    def __init__(self, model: str, texto: str, tokens_in: int, tokens_out: int, numero: int) -> None:
        self.id = "msg_fake_%06d" % numero
        self.model = model
        self.content = [_BloqueTexto(texto)]
        self.usage = _Uso(tokens_in, tokens_out)


class _Flujo:
    """Context manager devuelto por messages.stream(); genera el mensaje al pedirlo."""

    def __init__(self, generar) -> None:
        self._generar = generar
        self._mensaje = None

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def get_final_message(self) -> _Mensaje:
        if self._mensaje is None:
            self._mensaje = self._generar()
        return self._mensaje


# --------------------------------------------------------------------------- lógica
def _texto_de(contenido) -> str:
    if contenido is None:
        return ""
    if isinstance(contenido, str):
        return contenido
    partes = []
    for bloque in contenido:
        partes.append(bloque.get("text", "") if isinstance(bloque, dict) else getattr(bloque, "text", ""))
    return "".join(partes)


def _prompt_usuario(messages) -> str:
    for mensaje in reversed(messages or []):
        rol = mensaje.get("role") if isinstance(mensaje, dict) else getattr(mensaje, "role", None)
        if rol == "user":
            contenido = mensaje.get("content") if isinstance(mensaje, dict) else getattr(mensaje, "content", "")
            return _texto_de(contenido)
    raise ValueError("messages no contiene ningún mensaje con role='user'")


def _tarea_de(prompt: str) -> str:
    primera = prompt.lstrip("\ufeff \t\r\n").split("\n", 1)[0].strip()
    coincide = re.fullmatch(r"TAREA:\s*(\w+)", primera)
    if not coincide:
        raise ValueError(
            "La primera línea del prompt de usuario debe ser 'TAREA: <nombre>' (llegó: %r)" % primera[:80]
        )
    tarea = coincide.group(1)
    if tarea not in TAREAS:
        raise ValueError("TAREA desconocida: %r. Tareas válidas: %s" % (tarea, ", ".join(TAREAS)))
    return tarea


def _escenario() -> str:
    escenario = os.environ.get("FAKE_ESCENARIO", "normal").strip() or "normal"
    if escenario not in ESCENARIOS:
        raise ValueError(
            "FAKE_ESCENARIO desconocido: %r. Válidos: %s" % (escenario, ", ".join(ESCENARIOS))
        )
    return escenario


def _factor_demora() -> float:
    try:
        return float(os.environ.get("FAKE_DEMORA", "1"))
    except ValueError:
        return 1.0


def _dormir(tarea: str) -> float:
    factor = _factor_demora()
    if factor <= 0:
        return 0.0
    segundos = random.uniform(_DEMORA_MIN, _DEMORA_MAX) * factor * _TAREAS_LENTAS.get(tarea, 1.0)
    time.sleep(segundos)
    return segundos


def _respuesta_valida(tarea: str) -> str:
    """JSON válido; a veces envuelto en cercas para probar la extracción."""
    texto = json.dumps(respuestas.RESPUESTAS[tarea], ensure_ascii=False, indent=2)
    if tarea == "linea_tiempo":
        return "```json\n" + texto + "\n```"
    if tarea == "recuperacion_mejoras":
        return "```\n" + texto + "\n```"
    return texto


def _decidir(tarea: str, prompt: str, escenario: str, n_llamada: int):
    """Devuelve (texto, es_valida) según el escenario."""
    es_reintento = re.search(r"(?m)^REINTENTO:", prompt) is not None
    if escenario == "reintento" and tarea == "mitre_indicadores" and not es_reintento and n_llamada == 1:
        return _TEXTO_NO_JSON, False
    if escenario == "falla_worker" and tarea == "contencion_erradicacion":
        return _JSON_INVALIDO_CONTENCION, False
    if escenario == "falla_sintesis" and tarea == "sintesis":
        return _JSON_INVALIDO_SINTESIS, False
    return _respuesta_valida(tarea), True


def _generar(model, max_tokens, system, prompt: str, tarea: str, extra) -> _Mensaje:
    escenario = _escenario()
    with _LOCK:
        n_llamada = _CONTADORES.get(tarea, 0) + 1
        _CONTADORES[tarea] = n_llamada
        numero = sum(_CONTADORES.values())
    texto, es_valida = _decidir(tarea, prompt, escenario, n_llamada)
    demora = _dormir(tarea)
    tokens_in = max(1, (len(_texto_de(system)) + len(prompt)) // 4)
    tokens_out = max(1, len(texto) // 4)
    with _LOCK:
        _REGISTRO.append(
            {
                "tarea": tarea,
                "modelo": model,
                "max_tokens": max_tokens,
                "extra": sorted(extra),
                "escenario": escenario,
                "valida": es_valida,
                "reintento": re.search(r"(?m)^REINTENTO:", prompt) is not None,
                "demora": demora,
            }
        )
    return _Mensaje(model, texto, tokens_in, tokens_out, numero)


class _Mensajes:
    def _preparar(self, model, max_tokens, system, messages, extra):
        prompt = _prompt_usuario(messages)
        tarea = _tarea_de(prompt)  # falla pronto (ValueError) si la tarea es desconocida
        return lambda: _generar(model, max_tokens, system, prompt, tarea, extra)

    def stream(self, model=None, max_tokens=None, system=None, messages=None, **kw) -> _Flujo:
        return _Flujo(self._preparar(model, max_tokens, system, messages, kw))

    def create(self, model=None, max_tokens=None, system=None, messages=None, **kw) -> _Mensaje:
        return self._preparar(model, max_tokens, system, messages, kw)()


class Anthropic:
    """Cliente falso: no necesita api_key ni red."""

    def __init__(self, api_key=None, **kw) -> None:
        self.api_key = api_key
        self.messages = _Mensajes()


# --------------------------------------------------------------------------- utilidades de prueba
def estadisticas() -> dict:
    """Copia de los contadores: llamadas totales, por tarea y registro de cada llamada."""
    with _LOCK:
        return {
            "llamadas": sum(_CONTADORES.values()),
            "por_tarea": dict(_CONTADORES),
            "registro": [dict(entrada) for entrada in _REGISTRO],
        }


def _reset() -> None:
    """Pone a cero contadores y registro (el estado es global del proceso)."""
    with _LOCK:
        _CONTADORES.clear()
        _REGISTRO.clear()
