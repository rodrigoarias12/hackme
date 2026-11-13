"""hackme — agente de seguridad: busca vulnerabilidades, junta evidencia y propone el arreglo.

uso: bin/hackme <comando>

  doctor       qué está, qué falta y cómo se arregla: lo obligatorio, cada fuente y la rutina
               (--json para un agente · --rapido: solo lo obligatorio)
  config       la configuración guardada (~/.config/hackme/config.env)
               config poner HACKME_GITHUB <carpeta> · config quitar <clave>
  init         crea el repo privado de informes y memoria si no existe
  ronda        inventario + Aguara + Radar + AWS -> estado/ronda.json
  inventario   solo el inventario -> estado/inventario.json
  radar        bajar Radar y cruzar con el último inventario
  aguara       solo el escaneo de repos con Aguara
  aws          solo los hallazgos de GuardDuty, Security Hub e Inspector
  vercel       solo Vercel: equipo, variables, previews, firewall y auditoría
  vigia        la guardia de 15 minutos: ataques en curso, avisa por Telegram
               (--sin-avisar: imprime lo que avisaría y no guarda nada)
  caminos      caminos de ataque a lo más valioso, con la última ronda
  investigar   abre o refresca una investigación por cada pista seria, con su evidencia
               investigar ver <id> · investigar lista
               investigar objetivos (qué repo revisar a fondo) · investigar cazado <carpeta>
               investigar abrir <carpeta> --titulo "..." --severidad S --afirmacion "..."
               investigar anotar <id> [--estado E] [--tipo T --que "..." --donde "..."] [--proxima "..."]
  acciones     lo que hackme propone hacer: un PR con el arreglo, solo con el OK del dueño
               acciones proponer <investigación> --titulo "..." --plan "..."
               acciones aprobar <id> [--ok "palabras textuales del dueño"] · rechazar <id>
               acciones preparar <id> · cerrar <id> --pr <url>
  huella       qué hizo el agente en las últimas 26 h, contra sus reglas
               (o pasale archivos .jsonl de sesiones de Claude Code)

Configuración: `bin/hackme config` o variables de entorno (ver AGENTS.md). Para instalarlo con un
agente: skills/hackme-setup/SKILL.md. Códigos de salida: 0 ok,
1 error, 2 falta algo (doctor).
"""
import json
import os
import subprocess
import sys
import time

from . import inventario, rutas


def _inventario():
    t = time.time()
    inv = inventario.armar()
    inventario.guardar(inv)
    n_pkgs = sum(len(v) for r in inv["repos"].values() for v in r["paquetes"].values())
    print(f"inventario: {len(inv['repos'])} repos, {n_pkgs} paquetes, {len(inv['mac']['apps'])} apps "
          f"({time.time() - t:.0f}s)")
    return inv


def init():
    """Crea el repo privado (git init) con sus carpetas. No lo publica en ningún lado."""
    rutas.INFORMES.mkdir(parents=True, exist_ok=True)
    rutas.MEMORIA.mkdir(parents=True, exist_ok=True)
    if not (rutas.PRIVADO / ".git").is_dir():
        subprocess.run(["git", "init", "-q", "-b", "main", str(rutas.PRIVADO)], check=True)
        (rutas.PRIVADO / "README.md").write_text(
            "# hackme-privado\n\nInformes y memoria de hackme. **Nunca hacer público este repo.**\n")
    print(f"repo privado listo en {rutas.PRIVADO}. Si lo subís a GitHub, que sea privado.")


def _config(args):
    """Muestra o cambia la configuración guardada. El entorno siempre manda sobre el archivo."""
    guardado = rutas.leer_config()
    if args[:1] in (["poner"], ["set"]) and len(args) == 3:
        clave, valor = args[1], args[2]
        if clave not in rutas.CLAVES:
            sys.exit(f"config: {clave} no es una clave conocida. Las que hay: {', '.join(rutas.CLAVES)}")
        if clave == "HACKME_MODO" and valor not in ("todo", "nube", "mac"):
            sys.exit("config: HACKME_MODO es todo, nube o mac")
        guardado[clave] = valor
    elif args[:1] in (["quitar"], ["unset"]) and len(args) == 2:
        guardado.pop(args[1], None)
    elif args:
        sys.exit("uso: bin/hackme config · config poner <CLAVE> <valor> · config quitar <CLAVE>")
    if args:
        rutas.CONFIG.parent.mkdir(parents=True, exist_ok=True)
        rutas.CONFIG.write_text("# Configuración de hackme. La escribe `bin/hackme config poner`. Acá no van secretos.\n"
                                + "".join(f"{k}={v}\n" for k, v in sorted(guardado.items())))
        rutas.CONFIG.chmod(0o600)
        print(f"guardado en {rutas.CONFIG}")
    for clave in rutas.CLAVES:
        if clave in guardado and os.environ.get(clave) in (None, guardado[clave]):
            print(f"  {clave:18} {guardado[clave]}  (archivo)")
        elif clave in os.environ and not args:
            print(f"  {clave:18} {os.environ[clave]}  (entorno{', pisa al archivo' if clave in guardado else ''})")
        elif clave in guardado:
            print(f"  {clave:18} {guardado[clave]}  (archivo; en esta sesión manda el entorno)")
        else:
            print(f"  {clave:18} (por defecto)")


def _opcion(args, nombre):
    return args[args.index(nombre) + 1] if nombre in args and args.index(nombre) + 1 < len(args) else None


def _investigar(args):
    from . import investigar
    if args[:1] == ["ver"] and len(args) > 1:
        print(investigar.ficha(investigar.leer(args[1])))
    elif args[:1] == ["lista"]:
        for i in sorted(investigar.todas(), key=lambda i: (i["estado"] != "pista", i["severidad"] != "crítica", i["id"])):
            if i["estado"] != "arreglada" or "--todas" in args:
                print(f"{i['id']:44} {i['estado']:11} {i['severidad']:8} {(i.get('fuente') or ''):18} {i['titulo'][:70]}")
    elif args[:1] == ["objetivos"]:
        ronda = json.loads((rutas.ESTADO / "ronda.json").read_text())
        for o in investigar.objetivos(ronda)[:10]:
            print(f"{o['puntos']:5.1f}  {o['carpeta']:24} {'; '.join(o['motivos'])}")
    elif args[:1] == ["cazado"] and len(args) > 1:
        print(f"{args[1]}: revisado a fondo el {investigar.cazado(args[1])}")
    elif args[:1] == ["abrir"] and len(args) > 1:
        print(investigar.ficha(investigar.abrir(args[1], _opcion(args, "--titulo"), _opcion(args, "--severidad"), _opcion(args, "--afirmacion"))))
    elif args[:1] == ["anotar"] and len(args) > 1:
        inv = investigar.anotar(args[1], estado=_opcion(args, "--estado"), tipo=_opcion(args, "--tipo"), que=_opcion(args, "--que"),
                                donde=_opcion(args, "--donde") or "", proxima=_opcion(args, "--proxima"))
        print(investigar.ficha(inv))
    else:
        ronda = json.loads((rutas.ESTADO / "ronda.json").read_text())
        ronda["investigaciones"] = investigar.correr(ronda)
        (rutas.ESTADO / "ronda.json").write_text(json.dumps(ronda, ensure_ascii=False, indent=1))
        print(investigar.resumen(ronda["investigaciones"]))


def _acciones(args):
    from . import acciones
    verbo, quien = (args + [None, None])[:2]
    if verbo == "proponer" and quien:
        a = acciones.proponer(quien, _opcion(args, "--titulo"), _opcion(args, "--plan"))
        print(acciones.linea(a) + "\naviso: " + acciones.aviso(a))
    elif verbo == "aprobar" and quien:
        print(acciones.linea(acciones.aprobar(quien, _opcion(args, "--ok"))))
    elif verbo == "rechazar" and quien:
        print(acciones.linea(acciones.rechazar(quien, _opcion(args, "--motivo") or "")))
    elif verbo == "preparar" and quien:
        carpeta = acciones.preparar(quien)
        print(f"listo: {carpeta} en la rama {acciones.rama(quien)}. El arreglo va ahí y sale como PR; "
              "nunca se mergea, se deploya ni se empuja a la rama principal.")
    elif verbo == "cerrar" and quien:
        print(acciones.linea(acciones.cerrar(quien, _opcion(args, "--pr"))))
    else:
        print(acciones.resumen())


def main(args):
    comando = args[0] if args else "ronda"
    if comando in ("-h", "--help", "help"):
        print(__doc__)
    elif comando == "doctor":
        from . import doctor
        doctor.correr(args[1:])
    elif comando == "config":
        _config(args[1:])
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
    elif comando == "caminos":
        from . import caminos
        ronda = json.loads((rutas.ESTADO / "ronda.json").read_text())
        ronda["caminos"] = caminos.correr(ronda)
        (rutas.ESTADO / "ronda.json").write_text(json.dumps(ronda, ensure_ascii=False, indent=1))
        print(caminos.resumen(ronda["caminos"]))
    elif comando in ("investigar", "acciones"):
        try:
            (_investigar if comando == "investigar" else _acciones)(args[1:])
        except (ValueError, OSError, subprocess.CalledProcessError) as e:
            sys.exit(f"{comando}: {e}")
    elif comando == "huella":
        from . import huella
        print(huella.resumen(huella.correr([a for a in args[1:] if not a.startswith("-")] or None)))
    elif comando == "vigia":
        from . import vigia
        print(vigia.resumen(vigia.correr(enviar="--sin-avisar" not in args)))
    elif comando == "ronda":
        from . import ronda
        print(ronda.correr(_inventario()))
    else:
        sys.exit(__doc__)


main(sys.argv[1:])
