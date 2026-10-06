"""Regenera reportes/reporte_demo.json con el cliente falso (sin API y sin gastar créditos).

Uso, desde la raíz del repo:
    python tests/generar_reporte_demo.py              # sobrescribe reportes/reporte_demo.json
    python tests/generar_reporte_demo.py SALIDA.json  # escribe en otra ruta

Ejecuta soc_tutor.py sobre ejemplo_auth.log con el paquete `anthropic` falso de tests/fake/
(escenario "normal") dentro de una carpeta temporal, y marca el reporte con "_demo": true y
una nota. El dashboard muestra un banner cuando ve esa marca.
Las respuestas de los "modelos" son datos pregrabados: no son un análisis real. Aquí el
cliente falso simula demoras (FAKE_DEMORA=1) para que las barras de tiempo del dashboard
no salgan vacías; las pruebas, en cambio, lo usan sin demora (FAKE_DEMORA=0).
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
SCRIPT = RAIZ / "soc_tutor.py"
LOG_EJEMPLO = RAIZ / "ejemplo_auth.log"
CLIENTE_FALSO = RAIZ / "tests" / "fake"
DESTINO_POR_DEFECTO = RAIZ / "reportes" / "reporte_demo.json"
NOTA_DEMO = (
    "Reporte de demostración: las respuestas de los modelos fueron escritas a mano (cliente falso) "
    "y las métricas son estimaciones; no lo generó la API."
)
TIEMPO_MAXIMO = 120   # segundos
DEMORA_DEMO = "1"     # factor de la demora simulada al regenerar la demo


def entorno_con_cliente_falso(escenario="normal", clave="falsa", demora="0"):
    """Entorno de un subproceso que usa el paquete `anthropic` falso y no toca la red.

    Se borran las variables ANTHROPIC_* y FAKE_* heredadas para que una clave real
    o un escenario olvidado nunca se cuelen en las pruebas. Con clave=None no se define
    ANTHROPIC_API_KEY (sirve para probar el error de clave ausente). `demora` es el factor
    de FAKE_DEMORA: "0" no duerme (pruebas), "1" simula la latencia de una llamada real.
    """
    entorno = {k: v for k, v in os.environ.items() if not k.startswith(("ANTHROPIC_", "FAKE_"))}
    entorno.update(PYTHONPATH=str(CLIENTE_FALSO), FAKE_ESCENARIO=escenario, FAKE_DEMORA=str(demora),
                   PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
    if clave is not None:
        entorno["ANTHROPIC_API_KEY"] = clave
    return entorno


def ejecutar_soc_tutor(argumentos, cwd, entorno, tiempo_maximo=TIEMPO_MAXIMO):
    """Corre soc_tutor.py como lo haría un usuario y devuelve el CompletedProcess (texto UTF-8)."""
    return subprocess.run([sys.executable, str(SCRIPT), *argumentos], cwd=cwd, env=entorno,
                          capture_output=True, text=True, encoding="utf-8", timeout=tiempo_maximo)


def generar_reporte_demo(demora=DEMORA_DEMO):
    with tempfile.TemporaryDirectory() as temporal:
        proceso = ejecutar_soc_tutor([str(LOG_EJEMPLO)], temporal,
                                     entorno_con_cliente_falso(demora=demora))
        if proceso.returncode != 0:
            raise SystemExit(f"soc_tutor.py terminó con código {proceso.returncode}:\n"
                             f"{proceso.stderr or proceso.stdout}")
        reporte = json.loads((Path(temporal) / "reportes" / "reporte.json").read_text(encoding="utf-8"))
    return {**reporte, "_demo": True, "_nota": NOTA_DEMO}


def main(argv):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    destino = Path(argv[1]) if len(argv) > 1 else DESTINO_POR_DEFECTO
    destino.parent.mkdir(parents=True, exist_ok=True)
    texto = json.dumps(generar_reporte_demo(), ensure_ascii=False, indent=2) + "\n"
    destino.write_text(texto, encoding="utf-8", newline="\n")
    print(f"Reporte de demostración escrito en {destino}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
