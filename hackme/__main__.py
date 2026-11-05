"""hackme — agente de seguridad que solo observa.

uso: bin/hackme <comando>

  doctor       chequea lo necesario y dice qué falta (correr primero)
  init         crea el repo privado de informes y memoria si no existe
  ronda        inventario + Aguara + Radar + AWS -> estado/ronda.json
  inventario   solo el inventario -> estado/inventario.json
  radar        bajar Radar y cruzar con el último inventario
  aguara       solo el escaneo de repos con Aguara
  aws          solo los hallazgos de GuardDuty, Security Hub e Inspector
  vercel       solo Vercel: equipo, variables, previews, firewall y auditoría
  vigia        la guardia de 15 minutos: ataques en curso, avisa por Telegram
               (--sin-avisar: imprime lo que avisaría y no guarda nada)

Configuración por variables de entorno: ver AGENTS.md. Códigos de salida: 0 ok,
1 error, 2 falta algo (doctor).
"""
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import inventario, rutas


def _inventario():
    t = time.time()
    inv = inventario.armar()
    inventario.guardar(inv)
    n_pkgs = sum(len(v) for r in inv["repos"].values() for v in r["paquetes"].values())
    print(f"inventario: {len(inv['repos'])} repos, {n_pkgs} paquetes, {len(inv['mac']['apps'])} apps "
          f"({time.time() - t:.0f}s)")
    return inv


def _version(args):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=20)
        return (r.stdout or r.stderr).strip().splitlines()[0] if r.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return None


def doctor():
    """Imprime un chequeo por línea: ok / falta / opcional. Sale 2 si falta algo obligatorio."""
    falta = False

    def linea(estado, que, detalle):
        nonlocal falta
        falta |= estado == "falta"
        print(f"  {estado:8} {que:22} {detalle}")

    print(f"hackme doctor (modo {rutas.MODO})")
    linea("ok" if sys.version_info >= (3, 11) else "falta", "python >= 3.11", sys.version.split()[0])
    for herramienta in ("git", "rsync", "grep"):
        linea("ok" if shutil.which(herramienta) else "falta", herramienta, shutil.which(herramienta) or "no está en el PATH")
    aguara = _version([rutas.AGUARA, "version"])
    linea("ok" if aguara else "falta", "aguara", f"{rutas.AGUARA} ({aguara})" if aguara else
          f"no está en {rutas.AGUARA}: go install github.com/garagon/aguara/cmd/aguara@latest, o HACKME_AGUARA")
    linea("ok" if rutas.GITHUB.is_dir() else "falta", "carpeta de repos", f"{rutas.GITHUB} (HACKME_GITHUB)")
    if rutas.GITHUB.is_dir():
        linea("ok", "repos a revisar", f"{len(rutas.repos())} en modo {rutas.MODO}")
    privado_ok = (rutas.PRIVADO / ".git").is_dir()
    linea("ok" if privado_ok else "falta", "repo privado", f"{rutas.PRIVADO} (HACKME_PRIVADO)"
          + ("" if privado_ok else " — correr: bin/hackme init"))
    aws = _version(["aws", "--version"])
    linea("ok" if aws else "opcional", "aws cli", aws or "sin AWS: la ronda saltea GuardDuty/Security Hub/Inspector")
    telegram = all(os.environ.get(k) for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID")) or \
        (Path.home() / ".config" / "hackme" / "telegram.env").exists()
    linea("ok" if telegram else "opcional", "telegram", "configurado" if telegram else
          "sin avisos por Telegram: ver AGENTS.md")
    sys.exit(2 if falta else 0)


def init():
    """Crea el repo privado (git init) con sus carpetas. No lo publica en ningún lado."""
    rutas.INFORMES.mkdir(parents=True, exist_ok=True)
    rutas.MEMORIA.mkdir(parents=True, exist_ok=True)
    if not (rutas.PRIVADO / ".git").is_dir():
        subprocess.run(["git", "init", "-q", "-b", "main", str(rutas.PRIVADO)], check=True)
        (rutas.PRIVADO / "README.md").write_text(
            "# hackme-privado\n\nInformes y memoria de hackme. **Nunca hacer público este repo.**\n")
    print(f"repo privado listo en {rutas.PRIVADO}. Si lo subís a GitHub, que sea privado.")


def main(args):
    comando = args[0] if args else "ronda"
    if comando in ("-h", "--help", "help"):
        print(__doc__)
    elif comando == "doctor":
        doctor()
    elif comando == "init":
        init()
    elif comando == "inventario":
        _inventario()
    elif comando == "radar":
        from . import radar
        inv = json.loads((rutas.ESTADO / "inventario.json").read_text())
        print(radar.resumen(radar.correr(inv)))
    elif comando == "aguara":
        from . import aguara
        print(aguara.resumen(aguara.correr()))
    elif comando == "aws":
        from . import aws
        print(aws.resumen(aws.correr()))
    elif comando == "vercel":
        from . import vercel
        print(vercel.resumen(vercel.correr()))
    elif comando == "vigia":
        from . import vigia
        print(vigia.resumen(vigia.correr(enviar="--sin-avisar" not in args)))
    elif comando == "ronda":
        from . import ronda
        print(ronda.correr(_inventario()))
    else:
        sys.exit(__doc__)


main(sys.argv[1:])
