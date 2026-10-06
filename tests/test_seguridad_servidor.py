"""Seguridad del servidor local de SOC Tutor (unittest, solo librería estándar).

Desde la raíz del repo:
    python -B -m unittest discover -s tests -v

Comprueba que el servidor solo atiende peticiones con Host y Origin locales (defensa contra
DNS rebinding y contra páginas ajenas que abran /events y disparen el pipeline) y que
--dry-run no imprime la ruta completa del log. El servidor corre en el mismo proceso, en un
puerto libre al azar; no hay red externa ni API.
"""

import http.client
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
CARPETA_TESTS = Path(__file__).resolve().parent
RAIZ = CARPETA_TESTS.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(CARPETA_TESTS))

import soc_tutor as st  # noqa: E402
from generar_reporte_demo import ejecutar_soc_tutor, entorno_con_cliente_falso  # noqa: E402

LOG_EJEMPLO = RAIZ / "ejemplo_auth.log"
ESPERA_NO_ARRANQUE = 0.3     # segundos que se espera para confirmar que el pipeline NO arrancó


class TestHostYOrigin(unittest.TestCase):
    def setUp(self):
        self.arrancado = threading.Event()

    def al_conectar(self):
        """Simula el pipeline: marca la bandera y publica un historial mínimo."""
        self.arrancado.set()
        self.bus.publicar({"tipo": "inicio"})
        self.bus.publicar({"tipo": "fin"})

    def levantar(self, con_bus=False):
        """Servidor en proceso con puerto 0 (libre al azar); devuelve el puerto real."""
        self.bus = st.BusEventos() if con_bus else None
        servidor = st.ServidorSOC(("127.0.0.1", 0), "<html>hola</html>", self.bus,
                                  self.al_conectar if con_bus else None)
        threading.Thread(target=servidor.serve_forever, daemon=True).start()
        self.addCleanup(servidor.server_close)
        self.addCleanup(servidor.shutdown)
        return servidor.server_address[1]

    @staticmethod
    def pedir(puerto, ruta="/", **cabeceras):
        """GET con las cabeceras indicadas (http.client no añade Host si ya viene una)."""
        conexion = http.client.HTTPConnection("127.0.0.1", puerto, timeout=10)
        try:
            conexion.request("GET", ruta, headers=cabeceras)
            respuesta = conexion.getresponse()
            return respuesta.status, respuesta.read().decode("utf-8", errors="replace")
        finally:
            conexion.close()

    def test_host_valido_recibe_200(self):
        puerto = self.levantar()
        for host in (f"127.0.0.1:{puerto}", f"localhost:{puerto}", f"LOCALHOST:{puerto}"):
            with self.subTest(host=host):
                estado, cuerpo = self.pedir(puerto, Host=host)
                self.assertEqual(estado, 200)
                self.assertEqual(cuerpo, "<html>hola</html>")

    def test_host_ajeno_recibe_403_en_todas_las_rutas(self):
        puerto = self.levantar(con_bus=True)
        hosts = (f"evil.example:{puerto}", f"localhost:{puerto + 1}", "localhost",
                 f"127.0.0.1.evil.example:{puerto}")
        for host in hosts:
            for ruta in ("/", "/events", "/nada"):
                with self.subTest(host=host, ruta=ruta):
                    self.assertEqual(self.pedir(puerto, ruta, Host=host)[0], 403)
        self.assertFalse(self.arrancado.wait(ESPERA_NO_ARRANQUE))

    def test_sin_cabecera_host_recibe_403(self):
        puerto = self.levantar()
        conexion = http.client.HTTPConnection("127.0.0.1", puerto, timeout=10)
        self.addCleanup(conexion.close)
        conexion.putrequest("GET", "/", skip_host=True)
        conexion.endheaders()
        self.assertEqual(conexion.getresponse().status, 403)

    def test_origin_ajeno_en_events_recibe_403_y_no_arranca_el_pipeline(self):
        puerto = self.levantar(con_bus=True)
        for origen in ("https://evil.example", "null", f"http://localhost:{puerto}.evil.example",
                       f"https://localhost:{puerto}"):
            with self.subTest(origen=origen):
                estado, _ = self.pedir(puerto, "/events", Host=f"localhost:{puerto}", Origin=origen)
                self.assertEqual(estado, 403)
        self.assertFalse(self.arrancado.wait(ESPERA_NO_ARRANQUE), "el pipeline arrancó con un Origin ajeno")

    def test_origin_ajeno_en_la_pagina_recibe_403(self):
        puerto = self.levantar()
        estado, _ = self.pedir(puerto, "/", Host=f"localhost:{puerto}", Origin="https://evil.example")
        self.assertEqual(estado, 403)

    def test_origin_valido_recibe_200_y_arranca_el_pipeline(self):
        puerto = self.levantar(con_bus=True)
        for origen in (f"http://localhost:{puerto}", f"http://127.0.0.1:{puerto}"):
            with self.subTest(origen=origen):
                estado, cuerpo = self.pedir(puerto, "/events", Host=f"localhost:{puerto}", Origin=origen)
                self.assertEqual(estado, 200)
                self.assertIn('data: {"tipo": "fin"}', cuerpo)
        self.assertTrue(self.arrancado.wait(5))


class TestRutaDelLogOculta(unittest.TestCase):
    def test_dry_run_imprime_solo_el_nombre_del_archivo(self):
        with tempfile.TemporaryDirectory() as temporal:
            proceso = ejecutar_soc_tutor([str(LOG_EJEMPLO), "--dry-run"], temporal,
                                         entorno_con_cliente_falso(clave=None))
        self.assertEqual(proceso.returncode, 0, proceso.stderr)
        self.assertIn("=== Resumen del parseo: ejemplo_auth.log ===", proceso.stdout)
        for texto in (str(LOG_EJEMPLO), str(LOG_EJEMPLO.parent)):
            self.assertNotIn(texto, proceso.stdout + proceso.stderr)


if __name__ == "__main__":
    unittest.main()
