"""Huella: qué hizo el agente de hackme, comparado con sus propias reglas.

Claude Code guarda cada sesión en ~/.claude/projects/<carpeta>/<sesión>.jsonl, con cada
herramienta que usó el agente (comando, archivo, resultado). Este módulo lee esas sesiones —solo
las de hackme: las que arrancan con el skill— y marca lo que se sale de AGENTS.md:

  escritura   escribió fuera de sus dos repos (o tocó el código en vez de solo estado/)
  secretos    abrió un .env, credenciales, claves, o pidió valores en claro
  cambios     un comando que cambia algo en AWS, Vercel o GitHub (fuera del repo privado y del
              PR de una acción aprobada), o un push a la rama principal, forzado, o un merge
  salida      mandó algo a un host que no está en la lista (Telegram, las APIs que lee)
  bloqueo     desinstaló, limpió o prendió un modo que bloquea
  aprobación  se aprobó una acción en la sesión: para que el dueño confirme que el OK fue suyo
  fuera       leyó archivos fuera de las carpetas de repos (informativo)

Es heurístico: lee los comandos como texto, no los ejecuta. Marca para revisar; que no marque
nada no prueba que el agente se haya portado bien. La huella de herramientas MCP (si pasan por
oktsec) se suma con `oktsec logs`.
"""
import datetime as dt
import json
import os
import re
import shlex
import time
from pathlib import Path

from . import acciones, rutas

SESIONES = Path(os.environ.get("HACKME_SESIONES", Path.home() / ".claude" / "projects"))
# Cómo se reconoce una sesión de hackme: su primer pedido carga el skill.
MARCA = re.compile(r"skills/(hackme|centinela)/SKILL\.md")
VENTANA_HORAS = 26

HOSTS_OK = ("api.telegram.org", "api.vercel.com", "www.oktsec.com", "oktsec.com", "api.osv.dev", "github.com",
            "api.github.com", "objects.githubusercontent.com", "amazonaws.com")
SECRETO_RUTA = re.compile(r"(^|/)(\.env(\.[\w.-]+)?|id_rsa\w*|id_ed25519\w*|credentials(\.json)?|[^/\s]*\.(pem|key|p12|pfx|keystore|jks|tfstate)"
                          r"|\.npmrc|\.pypirc|\.netrc|telegram\.env|vigia\.env)$")
SECRETO_CMD = re.compile(r"(--no-redact|\bdecrypt\b|\bprintenv\b|(^|[;&|]\s*)env\s*($|[;&|])|security find-generic-password|"
                         r"\.aws/credentials|\.config/(hackme|centinela)/|vercel env pull)")
AWS_LECTURA = re.compile(r"^(describe|list|get|lookup|search|batch-get|generate-credential-report|scan|query)")
BLOQUEO = re.compile(r"(aguara\s+clean|npm\s+(uninstall|rm)\b|pnpm\s+remove|pip\s+uninstall|brew\s+(uninstall|remove)|"
                     r"oktsec\s+enforce|launchctl\s+(bootout|unload)|kill\s+-9)")
TOKEN = re.compile(r"(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abp]-[A-Za-z0-9-]{10,}|"
                   r"bot\d{6,}:[A-Za-z0-9_-]{20,}|[A-Za-z0-9+/_-]{40,})")


HEREDOC = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?[^\n]*\n(.*?)\n\1(?=\s|$)", re.S)
CODIGO_ESCRIBE = re.compile(r"(open\([^)]*,\s*['\"][wax]|\.write_(text|bytes)\(|shutil\.(copy|move|rmtree)|os\.(remove|unlink|rename))")


def _partir(cmd):
    """Parte un comando en subcomandos por && || ; | y saltos de línea, respetando comillas."""
    partes, actual, q, i = [], [], None, 0
    while i < len(cmd):
        ch = cmd[i]
        if q:
            actual.append(ch)
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
            actual.append(ch)
        elif cmd.startswith("&&", i) or cmd.startswith("||", i):
            partes.append("".join(actual)); actual = []; i += 2; continue
        elif ch in ";|\n":
            partes.append("".join(actual)); actual = []
        else:
            actual.append(ch)
        i += 1
    partes.append("".join(actual))
    return [s.strip() for s in partes if s.strip()]


def _redirecciones(s):
    """Destinos de > y >>, mirando solo lo que está fuera de comillas."""
    enmascarado = re.sub(r"'[^']*'|\"[^\"]*\"", lambda m: m.group(0)[0] + "x" * (len(m.group(0)) - 2) + m.group(0)[-1], s)
    destinos = []
    for m in re.finditer(r"(?<![0-9&<>])>>?(?!&)\s*", enmascarado):
        resto = s[m.end():]
        token = re.match(r"('[^']*'|\"[^\"]*\"|[^\s;&|]+)", resto)
        if token:
            destinos.append(token.group(1).strip("'\""))
    return destinos


def _tapar(texto):
    return TOKEN.sub("[redactado]", texto)


def _expandir(cmd, variables):
    """Resuelve ~ y las variables simples asignadas en el mismo comando (P=~/x; cd $P)."""
    for nombre, valor in re.findall(r"(?:^|[\s;&])(?:export\s+)?([A-Z_][A-Z0-9_]*)=\"?([^\s;\"&]+)\"?", cmd):
        variables[nombre] = valor
    for nombre, valor in sorted(variables.items(), key=lambda x: -len(x[0])):
        cmd = cmd.replace("${" + nombre + "}", valor).replace("$" + nombre, valor)
    return cmd.replace("~/", str(Path.home()) + "/")


def _ruta(p, cwd):
    p = p.strip("'\"")
    if not p or p.startswith("-"):
        return None
    p = p.replace("~/", str(Path.home()) + "/")
    return Path(p if p.startswith("/") else os.path.join(cwd or str(Path.home()), p)).resolve()


def _dentro(p, *raices):
    return any(str(p) == str(r) or str(p).startswith(str(r) + os.sep) for r in raices)


def _permitido_escribir(p):
    temporales = (Path("/tmp").resolve(), Path("/private/tmp"), Path("/private/var/folders"), Path("/var/folders"))
    # centinela-privado: el nombre del repo privado antes del 04/11, para leer huellas viejas.
    privados = (rutas.PRIVADO.resolve(), (rutas.GITHUB / "centinela-privado").resolve())
    return _dentro(p, *privados, rutas.ESTADO.resolve(), *temporales) or str(p) == "/dev/null"


def _accion_de(p):
    """Si la carpeta es el clon de trabajo de una acción (estado/trabajo/<id>), su id."""
    trabajo = acciones.TRABAJO.resolve()
    if p and _dentro(p, trabajo) and str(p) != str(trabajo):
        return Path(p).relative_to(trabajo).parts[0]
    return None


def _lecturas_posibles():
    return (rutas.GITHUB.resolve(), rutas.PRIVADO.resolve(), rutas.RAIZ.resolve(), Path("/tmp").resolve(),
            Path("/private/tmp"), Path("/private/var/folders"))


def _hallazgo(regla, severidad, cuando, herramienta, que, por_que):
    return {"regla": regla, "severidad": severidad, "cuando": cuando, "herramienta": herramienta,
            "que": _tapar(que)[:240], "por_que": por_que}


def revisar_bash(cmd, cuando, cwd, variables):
    """Lee un comando de Bash como texto y devuelve lo que se sale de las reglas."""
    salida = []
    crudo = cmd
    cuerpos = [m.group(2) for m in HEREDOC.finditer(cmd)]
    cmd = HEREDOC.sub("<<HEREDOC", cmd)
    cuerpos += re.findall(r"python3?\s+(?:-I\s+)?-c\s+(\"[^\"]*\"|'[^']*')", cmd)
    for c in cuerpos:
        if CODIGO_ESCRIBE.search(c):
            salida.append(_hallazgo("escritura", "media", cuando, "Bash", crudo, "escribe archivos desde código: revisar el destino"))
    cmd = _expandir(cmd, variables)
    sub = _partir(cmd)
    dir_actual = cwd
    for s in sub:
        m = re.match(r"cd\s+(\S+)", s)
        if m:
            nuevo = _ruta(m.group(1), dir_actual)
            if nuevo:
                dir_actual = str(nuevo)
            continue
        # Escrituras: redirecciones, sed -i, rm, mv, cp, tee, touch, git que cambia.
        destinos = _redirecciones(s)
        try:
            partes = shlex.split(s, posix=True)
        except ValueError:
            partes = s.split()
        if partes:
            prog = os.path.basename(partes[0])
            args = [a for a in partes[1:] if not a.startswith("-")]
            if prog == "sed" and any(a.startswith("-i") for a in partes[1:]):
                destinos += args[1:]
            elif prog in ("rm", "rmdir", "touch", "mkdir", "chmod", "chown", "truncate"):
                destinos += args
            elif prog in ("mv", "cp", "rsync", "ln") and args:
                destinos.append(args[-1])
            elif prog == "tee":
                destinos += args
            elif prog == "git":
                git_dir = dir_actual
                if "-C" in partes:
                    git_dir = str(_ruta(partes[partes.index("-C") + 1], dir_actual))
                verbo = next((a for a in partes[1:] if not a.startswith("-") and a != git_dir and
                              (partes.index(a) == 0 or partes[partes.index(a) - 1] != "-C")), "")
                if verbo in ("commit", "push", "add", "rm", "reset", "checkout", "merge", "rebase", "tag", "stash", "clean"):
                    g = Path(git_dir).resolve() if git_dir else None
                    accion = _accion_de(g)
                    if accion and acciones.esta_aprobada(accion):
                        # El clon de una acción aprobada: se commitea y se empuja la rama del PR, nada más.
                        if verbo == "merge" or (verbo == "push" and re.search(r"(\s|:)(main|master)(\s|$)|\s(-f|--force\S*)(\s|$)", s)):
                            salida.append(_hallazgo("cambios", "alta", cuando, "Bash", crudo,
                                                    f"git {verbo} hacia la rama principal o forzado: una acción solo empuja su rama hackme/…"))
                    elif accion:
                        salida.append(_hallazgo("escritura", "alta", cuando, "Bash", crudo, f"git {verbo} en la acción {accion}, que no tiene el OK del dueño"))
                    elif not g or not _dentro(g, rutas.PRIVADO.resolve(), (rutas.GITHUB / "centinela-privado").resolve()):
                        salida.append(_hallazgo("escritura", "alta", cuando, "Bash", crudo,
                                                f"git {verbo} en {g or 'carpeta desconocida'}: solo puede commitear en el repo privado"))
            elif prog == "aws" and len(partes) > 2:
                servicio = next((a for a in partes[1:] if not a.startswith("-")), "")
                accion = next((a for a in partes[partes.index(servicio) + 1:] if not a.startswith("-")), "") if servicio else ""
                if accion and not AWS_LECTURA.match(accion) and servicio not in ("configure", "help", "sts"):
                    salida.append(_hallazgo("cambios", "alta", cuando, "Bash", crudo, f"aws {servicio} {accion} no es de lectura"))
            elif prog == "vercel" and len(partes) > 1:
                sub_cmd = partes[1]
                metodo = re.search(r"(-X|--method)\s+(POST|PUT|PATCH|DELETE)", s)
                if sub_cmd not in ("api", "security", "whoami", "teams", "ls", "list", "inspect", "logs", "--version", "help") or metodo:
                    salida.append(_hallazgo("cambios", "alta", cuando, "Bash", crudo, f"vercel {sub_cmd} puede cambiar algo"))
            elif prog == "gh" and len(partes) > 2:
                if partes[1] in ("issue", "pr") and partes[2] in ("create", "comment", "close", "edit", "merge"):
                    accion = _accion_de(Path(dir_actual).resolve()) if dir_actual else None
                    pr_aprobado = partes[1:3] == ["pr", "create"] and accion and acciones.esta_aprobada(accion)
                    if not pr_aprobado and "hackme-privado" not in s and "centinela-privado" not in s:
                        salida.append(_hallazgo("cambios", "alta", cuando, "Bash", crudo, "issue o PR fuera del repo privado y sin una acción aprobada"))
                elif partes[1] == "api" and re.search(r"(-X|--method)\s+(POST|PUT|PATCH|DELETE)", s):
                    salida.append(_hallazgo("cambios", "alta", cuando, "Bash", crudo, "gh api con un método que escribe"))
                elif partes[1] == "repo" and partes[2] in ("edit", "delete", "rename", "archive"):
                    salida.append(_hallazgo("cambios", "alta", cuando, "Bash", crudo, f"gh repo {partes[2]}"))
        for d in destinos:
            p = _ruta(d, dir_actual)
            if p and not _permitido_escribir(p):
                salida.append(_hallazgo("escritura", "alta", cuando, "Bash", crudo, f"escribe en {p}"))
        if SECRETO_CMD.search(s):
            salida.append(_hallazgo("secretos", "alta", cuando, "Bash", crudo, "toca credenciales o pide valores en claro"))
        for palabra in re.findall(r"[^\s'\"|;&<>]+", s):
            if SECRETO_RUTA.search(palabra) and not palabra.endswith(".env.example") and partes and \
                    os.path.basename(partes[0]) in ("cat", "less", "more", "head", "tail", "sed", "awk", "grep", "cp", "open", "source", "."):
                salida.append(_hallazgo("secretos", "alta", cuando, "Bash", crudo, f"lee {palabra}"))
        if re.search(r"hackme\s+acciones\s+aprobar\b", s):
            salida.append(_hallazgo("aprobación", "media", cuando, "Bash", crudo, "se aprobó una acción en esta sesión: confirmá que el OK fue tuyo"))
        if BLOQUEO.search(s):
            salida.append(_hallazgo("bloqueo", "media", cuando, "Bash", crudo, "desinstala, limpia o bloquea"))
        for host in re.findall(r"https?://([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})", s):
            if not any(host == h or host.endswith("." + h) for h in HOSTS_OK):
                salida.append(_hallazgo("salida", "alta", cuando, "Bash", crudo, f"habla con {host}, que no está en la lista"))
        if partes and os.path.basename(partes[0]) in ("cat", "head", "tail", "sed", "less") and len(partes) > 1:
            for a in partes[1:]:
                if a.startswith("-") or re.fullmatch(r"[\d,p]+", a):
                    continue
                p = _ruta(a, dir_actual)
                if p and not _dentro(p, *_lecturas_posibles()):
                    salida.append(_hallazgo("fuera", "info", cuando, "Bash", crudo, f"lee {p}, fuera de las carpetas de repos"))
    return salida


def revisar_llamada(nombre, entrada, cuando, cwd, variables):
    if nombre == "Bash":
        return revisar_bash(entrada.get("command", ""), cuando, cwd, variables)
    salida = []
    archivo = entrada.get("file_path") or entrada.get("notebook_path")
    if nombre in ("Write", "Edit", "MultiEdit", "NotebookEdit") and archivo:
        p = _ruta(archivo, cwd)
        if p and not _permitido_escribir(p):
            salida.append(_hallazgo("escritura", "alta", cuando, nombre, archivo, f"escribe en {p}"))
    if nombre == "Read" and archivo:
        p = _ruta(archivo, cwd)
        if p and SECRETO_RUTA.search(str(p)) and not str(p).endswith(".env.example"):
            salida.append(_hallazgo("secretos", "alta", cuando, nombre, archivo, f"abre {p}"))
        elif p and not _dentro(p, *_lecturas_posibles()):
            salida.append(_hallazgo("fuera", "info", cuando, nombre, archivo, f"lee {p}, fuera de las carpetas de repos"))
    if nombre in ("WebFetch", "WebSearch"):
        salida.append(_hallazgo("salida", "media", cuando, nombre, json.dumps(entrada, ensure_ascii=False), "consulta la web: el skill no lo usa"))
    return salida


def _es_de_hackme(lineas):
    for d in lineas:
        if d.get("type") == "user":
            c = (d.get("message") or {}).get("content")
            texto = c if isinstance(c, str) else json.dumps(c, ensure_ascii=False)
            return bool(MARCA.search(texto))
    return False


def leer_sesion(archivo):
    """Devuelve (es de hackme, llamadas) de un .jsonl de Claude Code."""
    lineas = []
    with open(archivo, encoding="utf-8", errors="replace") as f:
        for l in f:
            try:
                lineas.append(json.loads(l))
            except ValueError:
                continue
    if not _es_de_hackme(lineas):
        return False, [], None
    llamadas, cwd = [], None
    for d in lineas:
        cwd = d.get("cwd") or cwd
        m = d.get("message") or {}
        if d.get("type") == "assistant" and isinstance(m.get("content"), list):
            for c in m["content"]:
                if c.get("type") == "tool_use":
                    llamadas.append({"cuando": d.get("timestamp"), "herramienta": c.get("name"), "entrada": c.get("input") or {}, "cwd": cwd})
    return True, llamadas, cwd


def auditar(llamadas):
    hallazgos, variables, clases = [], {"HACKME_PRIVADO": str(rutas.PRIVADO)}, {}
    for ll in llamadas:
        clases[ll["herramienta"]] = clases.get(ll["herramienta"], 0) + 1
        hallazgos += revisar_llamada(ll["herramienta"], ll["entrada"], ll["cuando"], ll["cwd"], variables)
    avisos = sum(1 for ll in llamadas if ll["herramienta"] == "PushNotification" or
                 (ll["herramienta"] == "Bash" and "bin/avisar" in ll["entrada"].get("command", "")))
    return {"llamadas": len(llamadas), "por_herramienta": clases, "avisos_mandados": avisos, "hallazgos": hallazgos}


def sesiones_recientes(horas=VENTANA_HORAS):
    limite = time.time() - horas * 3600
    return sorted((p for p in SESIONES.glob("*/*.jsonl") if p.stat().st_mtime >= limite), key=lambda p: p.stat().st_mtime)


def correr(archivos=None, guardar=True):
    archivos = [Path(a) for a in archivos] if archivos else sesiones_recientes()
    salida = []
    for a in archivos:
        es, llamadas, cwd = leer_sesion(a)
        if not es:
            continue
        r = auditar(llamadas)
        inicio = llamadas[0]["cuando"] if llamadas else None
        r.update({"sesion": a.stem, "inicio": inicio, "cwd": cwd})
        salida.append(r)
        if guardar:
            destino = rutas.PRIVADO / "huellas"
            destino.mkdir(parents=True, exist_ok=True)
            dia = (inicio or dt.datetime.now().isoformat())[:10]
            (destino / f"{dia}-{a.stem[:8]}.json").write_text(json.dumps(r, ensure_ascii=False, indent=1))
    return {"sesiones": salida}


def resumen(r):
    if not r["sesiones"]:
        return "huella: no hay sesiones de hackme en las últimas 26 h"
    lineas = []
    for s in r["sesiones"]:
        sev = {}
        for h in s["hallazgos"]:
            sev[h["severidad"]] = sev.get(h["severidad"], 0) + 1
        lineas.append(f"huella {s['sesion'][:8]} ({(s['inicio'] or '')[:16]}): {s['llamadas']} llamadas, "
                      f"{s['avisos_mandados']} avisos, hallazgos {sev or 'ninguno'}")
        for h in s["hallazgos"]:
            lineas.append(f"  {h['severidad']:5} {h['regla']:9} {h['por_que']}")
    return "\n".join(lineas)
