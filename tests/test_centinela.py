"""Tests sin red ni Aguara: el cruce con Radar, las capas de Aguara y los modos.

python3 -m unittest discover -s tests
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from centinela import aguara, radar, rutas  # noqa: E402

INVENTARIO = {
    "repos": {
        "api": {"paquetes": {"pypi": {"litellm": {"nombre": "litellm", "versiones": {"1.107.0": ["uv.lock"]}}},
                             "npm": {"events": {"nombre": "events", "versiones": {"3.3.0": ["package-lock.json"]}}}},
                "imagenes": ["node:22.17.0-alpine"], "servicios": ["railway"], "mcp": []},
    },
    "mac": {"apps": {"Cursor": "3.26.13"}, "brew": {}, "extensiones": {"cursor": {"anthropic.claude-code": "2.1.304"}},
            "runtimes": {"node.js": "25.6.1"}, "npm_global": {}, "mcp": {}},
}


def aviso(**campos):
    base = {"vendor": "", "products": [], "affected": [], "cve_details": [], "additional_evidence": {"packages": []}}
    return {**base, **campos}


class Cruce(unittest.TestCase):
    def setUp(self):
        self.idx = radar._indice(INVENTARIO)

    def test_version_afectada_por_osv(self):
        item = aviso(vendor="LiteLLM", products=["LiteLLM"], additional_evidence={"packages": [{
            "query": {"name": "litellm", "version": "1.107.0"},
            "records": [{"affected": [{"versions": ["1.82.7", "1.107.0"]}]}]}]})
        fuerzas = {c["fuerza"] for c in radar._cruzar(item, self.idx) if c["nombre"] == "litellm"}
        self.assertEqual(fuerzas, {"version-afectada"})

    def test_primera_palabra_del_producto(self):
        item = aviso(vendor="Google Brotli", products=["Brotli", "Node.js 22.x"])
        nombres = {c["nombre"] for c in radar._cruzar(item, self.idx)}
        self.assertIn("node.js", nombres)   # runtime de la Mac
        self.assertIn("node", nombres)      # imagen docker node:22…

    def test_extension_con_texto_extra(self):
        item = aviso(vendor="Cursor", products=["Anthropic.claude-code from Cursor Marketplace"])
        nombres = {c["nombre"] for c in radar._cruzar(item, self.idx)}
        self.assertEqual(nombres, {"Cursor", "anthropic.claude-code"})

    def test_texto_libre_no_coincide(self):
        # "events" aparece en el texto del producto pero no es el producto: no tiene que coincidir.
        item = aviso(vendor="Adobe", products=["Adobe Commerce events module"])
        self.assertEqual(radar._cruzar(item, self.idx), [])

    def test_servicio(self):
        item = aviso(vendor="Railway", products=["Railway"])
        self.assertEqual([c["tipo"] for c in radar._cruzar(item, self.idx)], ["servicio"])


class Capas(unittest.TestCase):
    def capa(self, archivo, regla="PROMPT_001", severidad="alta"):
        return aguara._capa({"archivo": archivo, "regla": regla, "severidad": severidad})

    def test_superficie_agentica(self):
        for archivo in (".claude/skills/x/SKILL.md", "CLAUDE.md", "sub/AGENTS.md", ".mcp.json",
                        ".github/workflows/ci.yml", "skills/foo.md", ".cursor/rules/a.mdc"):
            self.assertEqual(self.capa(archivo), "agéntica", archivo)

    def test_hooks_de_react_no_son_agenticos(self):
        self.assertEqual(self.capa("src/features/kyc/hooks/useKyc.ts"), "código")
        self.assertEqual(self.capa("dev/fixtures/agents/memoria.md"), "código")

    def test_credencial_critica(self):
        self.assertEqual(self.capa("src/config.ts", regla="CRED_013", severidad="crítica"), "credencial")


class Modos(unittest.TestCase):
    def test_mac_solo_carpetas_sin_remoto(self):
        with tempfile.TemporaryDirectory() as raiz:
            for nombre, remoto in (("con-remoto", True), ("sin-remoto", False), ("centinela-privado", False)):
                carpeta = Path(raiz) / nombre
                carpeta.mkdir()
                subprocess.run(["git", "init", "-q", str(carpeta)], check=True)
                if remoto:
                    subprocess.run(["git", "-C", str(carpeta), "remote", "add", "origin",
                                    "https://example.com/x.git"], check=True)
            antes = rutas.GITHUB, rutas.MODO
            try:
                rutas.GITHUB = Path(raiz)
                rutas.MODO = "mac"
                self.assertEqual([p.name for p in rutas.repos()], ["sin-remoto"])
                rutas.MODO = "nube"
                self.assertEqual([p.name for p in rutas.repos()], ["con-remoto", "sin-remoto"])
            finally:
                rutas.GITHUB, rutas.MODO = antes


class MemoriaAguara(unittest.TestCase):
    """Un scan que falla no puede borrar la memoria del repo (si no, mañana todo es "nuevo")."""

    def correr(self, raiz, respuestas):
        from unittest import mock
        hallazgo = {"rule_id": "CRED_021", "rule_name": "x", "severity": 3, "category": "c",
                    "file_path": "CLAUDE.md", "line": 1, "context": [{"is_match": True, "content": "l"}]}

        def falso(args):
            if args[1] == "scan":
                repo = Path(args[2]).name
                return {"error": "timeout"} if respuestas[repo] == "error" else {"findings": [hallazgo]}
            return {"findings": []}

        with mock.patch.object(aguara, "_json", side_effect=falso), \
             mock.patch.object(aguara, "espejar"), mock.patch.object(aguara, "secretos_versionados", return_value=[]):
            return aguara.correr()

    def test_scan_fallido_no_genera_falsos_nuevos(self):
        with tempfile.TemporaryDirectory() as raiz:
            raiz = Path(raiz)
            antes = rutas.GITHUB, rutas.ESPEJO, rutas.MEMORIA, rutas.ESTADO, rutas.MODO
            try:
                rutas.GITHUB, rutas.ESPEJO = raiz / "gh", raiz / "espejo"
                rutas.MEMORIA, rutas.ESTADO, rutas.MODO = raiz / "mem", raiz / "estado", "nube"
                for d in (rutas.GITHUB / "a", rutas.ESPEJO / "a", rutas.ESTADO):
                    d.mkdir(parents=True)
                primera = self.correr(raiz, {"a": "ok"})
                self.assertFalse(primera["repos"]["a"]["hallazgos"][0]["nuevo"])  # línea de base
                self.correr(raiz, {"a": "error"})                               # falla un día
                tercera = self.correr(raiz, {"a": "ok"})                         # vuelve
                self.assertFalse(tercera["repos"]["a"]["hallazgos"][0]["nuevo"])
            finally:
                rutas.GITHUB, rutas.ESPEJO, rutas.MEMORIA, rutas.ESTADO, rutas.MODO = antes


class Secretos(unittest.TestCase):
    def test_el_espejo_excluye_secretos(self):
        for patron in (".env", ".env.*", "*.pem", "*.key", "id_rsa*", "credentials*.json"):
            self.assertIn(patron, rutas.EXCLUIR_ESPEJO)
        self.assertEqual(rutas.INCLUIR_ESPEJO, [".env.example"])


if __name__ == "__main__":
    unittest.main()
