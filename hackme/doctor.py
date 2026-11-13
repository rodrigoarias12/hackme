"""doctor: qué hay, qué falta y cómo se arregla. No instala ni cambia nada: solo mira.

Lo lee una persona y lo lee el agente que instala hackme (`bin/hackme doctor --json`, ver
skills/hackme-setup/SKILL.md). Cada chequeo es {grupo, que, estado, detalle, arreglo}:

  ok        está y responde
  falta     es obligatorio y no está: la ronda no corre (código de salida 2)
  opcional  una fuente o un extra sin conectar: la ronda corre igual, pero no ve eso

Nunca imprime identificadores de cuenta, nombres de equipo ni valores de credenciales.
"""
import datetime
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import rutas

SETUP = "skills/hackme-setup/SKILL.md"


def _corre(args, espera=20):
    """(anduvo, primera línea de la salida). Nunca levanta."""
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=espera)
    except (OSError, subprocess.TimeoutExpired):
        return False, ""
    lineas = (r.stdout or r.stderr).strip().splitlines()
    return r.returncode == 0, lineas[0] if lineas else ""


def _uno(grupo, que, estado, detalle, arreglo=None):
    return {"grupo": grupo, "que": que, "estado": estado, "detalle": detalle, "arreglo": arreglo}


def base():
    """Lo obligatorio: sin esto la ronda no corre."""
    g, salida = "obligatorio", []
    nuevo = sys.version_info >= (3, 11)
    salida.append(_uno(g, "python >= 3.11", "ok" if nuevo else "falta", sys.version.split()[0],
                       None if nuevo else "instalar Python 3.11 o más nuevo (brew install python), o apuntar HACKME_PYTHON a uno"))
    for herramienta in ("git", "rsync", "grep"):
        donde = shutil.which(herramienta)
        salida.append(_uno(g, herramienta, "ok" if donde else "falta", donde or "no está en el PATH"))
    anduvo, version = _corre([rutas.AGUARA, "version"])
    salida.append(_uno(g, "aguara", "ok" if anduvo else "falta", f"{rutas.AGUARA} ({version})" if anduvo else f"no está en {rutas.AGUARA}",
                       None if anduvo else 'bin/hackme config poner HACKME_AGUARA "$(bin/instalar-aguara)" (baja el release oficial y '
                                           "verifica el checksum), o con Go: go install github.com/garagon/aguara/cmd/aguara@latest"))
    hay = rutas.GITHUB.is_dir()
    salida.append(_uno(g, "carpeta de repos", "ok" if hay else "falta",
                       f"{rutas.GITHUB}" + (f": {len(rutas.repos())} carpetas a revisar en modo {rutas.MODO}" if hay else " no existe"),
                       None if hay else "decir dónde están tus proyectos: bin/hackme config poner HACKME_GITHUB <carpeta>"))
    privado = (rutas.PRIVADO / ".git").is_dir()
    salida.append(_uno(g, "repo privado", "ok" if privado else "falta", f"{rutas.PRIVADO}",
                       None if privado else "bin/hackme init (git local; si lo subís a GitHub, que sea privado)"))
    return salida


def _github():
    if not shutil.which("gh"):
        return _uno("fuentes", "github", "opcional", "no está el CLI gh: no puede leer el código en GitHub ni abrir un PR",
                    "instalar gh (brew install gh) y que el dueño corra: gh auth login")
    anduvo, _ = _corre(["gh", "auth", "status"])
    return _uno("fuentes", "github", "ok" if anduvo else "opcional", "sesión de gh activa" if anduvo else "gh sin sesión",
                None if anduvo else "que el dueño corra: gh auth login")


def _aws():
    from . import aws
    if not shutil.which("aws"):
        return [_uno("fuentes", "aws", "opcional", "no está el CLI de AWS: la ronda saltea GuardDuty, Security Hub e Inspector",
                     f"si usás AWS: instalar el CLI y un perfil de solo lectura ({SETUP}, paso 5)")]
    salida = []
    perfiles = os.environ.get("HACKME_AWS", "default:us-east-1" if rutas.MODO != "nube" else ":us-east-1")
    for par in filter(None, perfiles.split(",")):
        perfil, _, region = par.partition(":")
        nombre = f"aws {perfil or '(ambiente)'}:{region}"
        try:
            aws._aws(perfil, region, "sts", "get-caller-identity")
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as e:
            salida.append(_uno("fuentes", nombre, "opcional", f"sin credenciales válidas: {str(e)[:120]}",
                               "renovar la sesión del perfil (aws sso login --profile …) o corregir HACKME_AWS"))
            continue
        salida.append(_uno("fuentes", nombre, "ok", "credenciales válidas"))
        # Las mismas llamadas de solo lectura que hace la ronda, pidiendo un solo resultado.
        servicios = (
            ("GuardDuty", lambda: bool(aws._aws(perfil, region, "guardduty", "list-detectors").get("DetectorIds")),
             "amenazas en la cuenta: accesos raros, credenciales usadas desde afuera"),
            ("Security Hub", lambda: aws._aws(perfil, region, "securityhub", "get-findings", "--max-items", "1") is not None,
             "configuraciones inseguras (buckets abiertos, MFA, puertos)"),
            ("Inspector", lambda: aws._aws(perfil, region, "inspector2", "list-findings", "--max-items", "1") is not None,
             "vulnerabilidades en servidores, contenedores y funciones"),
        )
        for servicio, prueba, para in servicios:
            try:
                prendido, motivo = prueba(), "sin detector en esta región"
            except (RuntimeError, ValueError, subprocess.TimeoutExpired) as e:
                prendido, motivo = False, str(e)[:120]
            salida.append(_uno("fuentes", f"  {servicio}", "ok" if prendido else "opcional",
                               "responde" if prendido else f"no responde ({motivo})",
                               None if prendido else f"sirve para ver {para}. Lo activa el dueño en la consola de AWS; "
                                                     "hackme nunca cambia nada en la cuenta"))
    return salida


def _vercel():
    from . import vercel
    if os.environ.get("VERCEL_TOKEN"):
        return _uno("fuentes", "vercel", "ok", "con VERCEL_TOKEN del entorno")
    if not shutil.which("vercel"):
        return _uno("fuentes", "vercel", "opcional", "sin VERCEL_TOKEN ni CLI de Vercel: la ronda saltea Vercel",
                    "si usás Vercel: npm i -g vercel y que el dueño corra: vercel login")
    try:
        vercel._alcance()
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as e:
        sin_sesion = "login_required" in str(e)
        return _uno("fuentes", "vercel", "opcional", "el CLI no tiene sesión" if sin_sesion else f"el CLI no responde: {str(e)[:100]}",
                    "que el dueño corra: vercel login")
    return _uno("fuentes", "vercel", "ok", "sesión del CLI activa")


def fuentes():
    """De dónde salen las señales. Todas opcionales salvo Radar y Aguara, que no piden cuenta."""
    return [_uno("fuentes", "oktsec radar", "ok", "público, no pide cuenta"), _github(), *_aws(), _vercel()]


def ultimo_informe(carpeta=None, hoy=None):
    """Días desde el último informe guardado (None si no hay ninguno)."""
    carpeta, hoy = carpeta or rutas.INFORMES, hoy or datetime.date.today()
    fechas = []
    for p in carpeta.glob("*.md") if carpeta.is_dir() else []:
        try:
            fechas.append(datetime.date.fromisoformat(p.name[:10]))
        except ValueError:
            pass
    return (hoy - max(fechas)).days if fechas else None


def rutina():
    """Lo que hace que hackme trabaje solo: la ronda diaria, el vigía y los avisos."""
    g, salida = "todos los días", []
    dias = ultimo_informe()
    al_dia = dias is not None and dias <= 2
    salida.append(_uno(g, "ronda diaria", "ok" if al_dia else "opcional",
                       "nunca dejó un informe" if dias is None else f"último informe hace {dias} día(s)",
                       None if al_dia else f"programar la ronda para que corra sola todos los días ({SETUP}, paso 7)"))
    from . import vigia
    cargado = sys.platform == "darwin" and "com.hackme.vigia" in (subprocess.run(
        ["launchctl", "list"], capture_output=True, text=True).stdout if shutil.which("launchctl") else "")
    salida.append(_uno(g, "vigía (15 min)", "ok" if cargado else "opcional",
                       "tarea de launchd cargada" if cargado else
                       ("configurado pero sin tarea que lo corra" if vigia.CONFIG.exists() else "sin configurar"),
                       None if cargado else "mira ataques en curso cada 15 minutos: docs/vigia.md"))
    telegram = all(os.environ.get(k) for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID")) or \
        (Path.home() / ".config" / "hackme" / "telegram.env").exists()
    salida.append(_uno(g, "telegram", "ok" if telegram else "opcional",
                       "configurado" if telegram else "sin avisos al teléfono: lo nuevo queda solo en el informe",
                       None if telegram else "ver la sección Telegram del README"))
    return salida


def chequeos(rapido=False):
    return base() + ([] if rapido else fuentes() + rutina())


def texto(lista):
    lineas, grupo = [f"hackme doctor (modo {rutas.MODO})"], None
    for c in lista:
        if c["grupo"] != grupo:
            grupo = c["grupo"]
            lineas.append(f"\n{grupo}")
        lineas.append(f"  {c['estado']:8} {c['que']:22} {c['detalle']}")
        if c["arreglo"]:
            lineas.append(f"  {'':8} {'':22} → {c['arreglo']}")
    faltan = [c["que"] for c in lista if c["estado"] == "falta"]
    sin = [c["que"].strip() for c in lista if c["estado"] == "opcional"]
    lineas.append("")
    lineas.append(f"Falta lo obligatorio: {', '.join(faltan)}." if faltan else "Lo obligatorio está: la ronda puede correr.")
    if sin:
        lineas.append(f"Sin conectar ({len(sin)}): {', '.join(sin)}.")
    return "\n".join(lineas)


def correr(args):
    lista = chequeos(rapido="--rapido" in args)
    listo = not any(c["estado"] == "falta" for c in lista)
    if "--json" in args:
        print(json.dumps({"modo": rutas.MODO, "listo": listo, "config": str(rutas.CONFIG), "chequeos": lista},
                         ensure_ascii=False, indent=1))
    else:
        print(texto(lista))
    sys.exit(0 if listo else 2)
