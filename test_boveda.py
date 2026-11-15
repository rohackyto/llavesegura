"""Pruebas del núcleo: .venv\\Scripts\\python.exe -m unittest -v"""
import tempfile
import unittest
from pathlib import Path

import pyotp

import almacen
import boveda as bv
import importar

PW = "una frase bastante larga"


class TestBoveda(unittest.TestCase):
    def setUp(self):
        self.srv = bv.llave_desde_texto(bv.nueva_llave_servidor())
        self.b, self.dek = bv.crear(PW, self.srv)

    def test_password_y_entradas(self):
        e = bv.nueva_entrada("OpenAI", "sk-proj-abcdefghijklmnop1234")
        bv.guardar_entradas(self.b, self.dek, [e])
        dek = bv.abrir_con_password(self.b, PW)
        self.assertEqual(bv.leer_entradas(self.b, dek)[0]["clave"], "sk-proj-abcdefghijklmnop1234")
        self.assertNotIn("sk-proj", str(self.b))  # nada en claro dentro de la bóveda
        with self.assertRaises(bv.ClaveIncorrecta):
            bv.abrir_con_password(self.b, "otra contraseña larga")

    def test_password_corta(self):
        with self.assertRaises(ValueError):
            bv.crear("corta", self.srv)

    def test_rapido_requiere_llave_correcta(self):
        self.assertEqual(bv.abrir_rapido(self.b, self.srv), self.dek)
        otra = bv.llave_desde_texto(bv.nueva_llave_servidor())
        with self.assertRaises(bv.SinLlaveServidor):
            bv.abrir_rapido(self.b, otra)
        with self.assertRaises(bv.SinLlaveServidor):
            bv.abrir_rapido(self.b, None)

    def test_rotar_llave_servidor(self):
        otra = bv.llave_desde_texto(bv.nueva_llave_servidor())
        self.assertFalse(bv.llave_servidor_vigente(self.b, otra))
        bv.envolver_servidor(self.b, self.dek, otra)
        self.assertEqual(bv.abrir_rapido(self.b, otra), self.dek)
        self.assertEqual(bv.leer_rapido(self.b, otra), bv.rapido_vacio())

    def test_rapido_alterado(self):
        self.b["rapido"]["ct"] = self.b["rapido"]["ct"][:-4] + "AAAA"
        with self.assertRaises(bv.SinLlaveServidor):
            bv.leer_rapido(self.b, self.srv)

    def test_pin(self):
        cfg = bv.rapido_vacio()
        cfg["pin"] = bv.hash_pin("482913")
        self.assertTrue(bv.pin_correcto(cfg, "482913"))
        self.assertFalse(bv.pin_correcto(cfg, "482914"))
        for malo in ("111111", "123456", "12345", "abcdef"):
            with self.assertRaises(ValueError):
                bv.hash_pin(malo)

    def test_totp_y_reuso(self):
        cfg = bv.rapido_vacio()
        cfg["totp"] = pyotp.random_base32()
        t = 1_800_000_000
        cod = pyotp.TOTP(cfg["totp"]).at(t)
        cont = bv.totp_correcto(cfg, cod, t)
        self.assertIsNotNone(cont)
        cfg["totp_ultimo"] = cont
        self.assertIsNone(bv.totp_correcto(cfg, cod, t))      # no se reutiliza
        self.assertIsNone(bv.totp_correcto(cfg, "000000", t + 300))

    def test_bloqueo(self):
        t = 1000.0
        for _ in range(bv.FALLOS_SIN_ESPERA):
            bv.registrar_fallo(self.b, t)
        self.assertEqual(bv.espera_restante(self.b, t), 0)
        bv.registrar_fallo(self.b, t)
        self.assertEqual(bv.espera_restante(self.b, t), bv.ESPERA_BASE)
        for _ in range(bv.FALLOS_MAX_RAPIDO):
            bv.registrar_fallo(self.b, t)
        self.assertTrue(bv.rapido_bloqueado(self.b))
        self.assertLessEqual(bv.espera_restante(self.b, t), bv.ESPERA_MAX)
        bv.registrar_exito(self.b)
        self.assertFalse(bv.rapido_bloqueado(self.b))

    def test_cambiar_password(self):
        bv.cambiar_password(self.b, self.dek, "nueva frase muy larga")
        self.assertEqual(bv.abrir_con_password(self.b, "nueva frase muy larga"), self.dek)
        with self.assertRaises(bv.ClaveIncorrecta):
            bv.abrir_con_password(self.b, PW)


class TestAlmacenLocal(unittest.TestCase):
    def test_conflicto(self):
        with tempfile.TemporaryDirectory() as d:
            a = almacen.AlmacenLocal(Path(d) / "b.json")
            self.assertEqual(a.cargar(), (None, None))
            v1 = a.guardar({"x": 1}, None)
            b, v = a.cargar()
            self.assertEqual((b, v), ({"x": 1}, v1))
            a.guardar({"x": 2}, v)
            with self.assertRaises(almacen.Conflicto):
                a.guardar({"x": 3}, v)   # versión vieja
            with self.assertRaises(almacen.Conflicto):
                a.guardar({"x": 3}, None)  # crear cuando ya existe


class TestImportar(unittest.TestCase):
    def test_formatos(self):
        txt = """# cuenta personal
OPENAI_API_KEY=sk-proj-AbCdEf1234567890xyz
export GEMINI_API_KEY="AIzaSyA1234567890abcdefghij"
Anthropic: sk-ant-api03-XyZ987654321abcdEFG
GitHub token
ghp_abcdefghijklmnopqrstuvwxyz0123456789
Supabase | eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
texto suelto sin clave
OPENAI_API_KEY=sk-proj-AbCdEf1234567890xyz
"""
        r = importar.analizar(txt)
        self.assertEqual([x["nombre"] for x in r],
                         ["OPENAI_API_KEY", "GEMINI_API_KEY", "Anthropic", "GitHub token", "Supabase"])
        self.assertEqual([x["servicio"] for x in r], ["OpenAI", "Google", "Anthropic", "GitHub", "Supabase"])
        self.assertEqual(r[0]["nota"], "cuenta personal")
        self.assertEqual(r[1]["clave"], "AIzaSyA1234567890abcdefghij")

    def test_mascara_y_env(self):
        self.assertEqual(importar.enmascarar("sk-proj-1234567890"), "sk-p••••••7890")
        self.assertEqual(importar.a_env([{"nombre": "Open AI (grifo)", "clave": "k"}]), "OPEN_AI_GRIFO=k\n")


if __name__ == "__main__":
    unittest.main()
