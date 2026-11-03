"""bin/centinela <ronda|inventario|radar|aguara>"""
import json
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


def main(args):
    comando = args[0] if args else "ronda"
    if comando == "inventario":
        _inventario()
    elif comando == "radar":
        from . import radar
        inv = json.loads((rutas.ESTADO / "inventario.json").read_text())
        print(radar.resumen(radar.correr(inv)))
    elif comando == "aguara":
        from . import aguara
        print(aguara.resumen(aguara.correr()))
    elif comando == "ronda":
        from . import ronda
        print(ronda.correr(_inventario()))
    else:
        sys.exit(__doc__)


main(sys.argv[1:])
