"""Acciones: lo único que hackme hace además de mirar, y solo con el OK del dueño.

Existe una sola acción: un PR con el arreglo en el repo afectado. El camino es siempre el mismo:

  propuesta   la escribe el agente desde una investigación confirmada: qué va a cambiar y por qué
  aprobada    la aprueba el dueño, una por una: en una terminal, o el agente citando textual su
              OK del chat. Una aprobación no vale para la acción siguiente
  en-curso    `preparar` clonó el repo en estado/trabajo/<id> y creó la rama hackme/<id>
  ejecutada   el PR está abierto y se anotó su URL
  rechazada   el dueño dijo que no

Lo que nunca pasa: mergear, deployar, empujar a la rama principal, tocar la copia de trabajo del
dueño, cambiar algo en AWS o Vercel, o probar el ataque contra un sistema. La ronda programada
propone y avisa; no aprueba ni ejecuta. Todo eso lo revisa la huella.

Se guarda en $HACKME_PRIVADO/acciones/<id>.json.
"""
import datetime
import json
import re
import shutil
import subprocess
import sys

from . import investigar, rutas

CARPETA = rutas.PRIVADO / "acciones"
TRABAJO = rutas.ESTADO / "trabajo"   # clones descartables: nunca la carpeta donde trabaja el dueño
ABIERTAS = ("propuesta", "aprobada", "en-curso")
APROBADAS = ("aprobada", "en-curso", "ejecutada")
PR = re.compile(r"^https://github\.com/([\w.-]+/[\w.-]+)/pull/\d+$")


def _ahora():
    return datetime.datetime.now().isoformat(timespec="minutes")


def _archivo(accion_id):
    return CARPETA / f"{accion_id}.json"


def leer(accion_id):
    if not _archivo(accion_id).exists():
        raise ValueError(f"no existe la acción {accion_id}")
    return json.loads(_archivo(accion_id).read_text())


def guardar(a):
    CARPETA.mkdir(parents=True, exist_ok=True)
    _archivo(a["id"]).write_text(json.dumps(a, ensure_ascii=False, indent=1))


def todas():
    return [json.loads(p.read_text()) for p in sorted(CARPETA.glob("*.json"))] if CARPETA.is_dir() else []


def rama(accion_id):
    return f"hackme/{accion_id}"


def esta_aprobada(accion_id):
    """Para la huella: ¿esta acción tiene el OK del dueño?"""
    try:
        return leer(accion_id)["estado"] in APROBADAS
    except (ValueError, OSError):
        return False


def _paso(a, estado, **extra):
    a["historia"].append({"cuando": _ahora(), "de": a["estado"], "a": estado, **extra})
    a["estado"] = estado
    guardar(a)
    return a


def proponer(inv_id, titulo, plan):
    inv = investigar.leer(inv_id)
    if inv["estado"] != "confirmada":
        raise ValueError(f"la investigación {inv_id} está {inv['estado']}: solo una confirmada puede proponer una acción")
    if not inv.get("repo"):
        raise ValueError(f"{inv_id} no vive en un repo de GitHub ({inv.get('donde') or inv.get('fuente')}): no hay PR posible; "
                         "los pasos van al informe para que los haga el dueño")
    if not titulo or not plan:
        raise ValueError("una propuesta lleva --titulo y --plan (qué archivos cambia y por qué)")
    accion_id = "pr-" + inv_id
    if _archivo(accion_id).exists() and leer(accion_id)["estado"] in ABIERTAS + ("ejecutada",):
        raise ValueError(f"ya hay una acción para esa investigación: {accion_id} ({leer(accion_id)['estado']})")
    a = {"id": accion_id, "tipo": "pr", "investigacion": inv_id, "repo": inv["repo"], "base": inv.get("rama") or "main", "rama": rama(accion_id),
         "titulo": titulo, "plan": plan, "severidad": inv["severidad"], "estado": "propuesta", "pr": None,
         "historia": [{"cuando": _ahora(), "de": None, "a": "propuesta"}]}
    guardar(a)
    return a


def aviso(a):
    """El texto para Telegram: sin detalle de la vulnerabilidad, solo qué se propone y cómo aprobar."""
    return (f"hackme propone un PR en {a['repo']} ({a['severidad']}): {a['titulo']}. "
            f"Para aprobarlo: bin/hackme acciones aprobar {a['id']}")


def aprobar(accion_id, ok=None):
    a = leer(accion_id)
    if a["estado"] != "propuesta":
        raise ValueError(f"{accion_id} está {a['estado']}: solo se aprueba una propuesta")
    if sys.stdin.isatty():
        print(f"{a['repo']}: {a['titulo']}\n{a['plan']}\n")
        if input("Escribí 'si' para aprobar este PR: ").strip().lower() not in ("si", "sí"):
            raise ValueError("no se aprobó")
        return _paso(a, "aprobada", por="terminal")
    if not ok or len(ok.strip()) < 2:
        raise ValueError("sin terminal, la aprobación lleva --ok con las palabras textuales del dueño en el chat")
    return _paso(a, "aprobada", por="chat", ok_citado=ok.strip()[:300])


def rechazar(accion_id, motivo=""):
    a = leer(accion_id)
    if a["estado"] not in ABIERTAS:
        raise ValueError(f"{accion_id} está {a['estado']}")
    return _paso(a, "rechazada", motivo=motivo[:300])


def preparar(accion_id):
    """Clona el repo en una carpeta descartable y crea la rama. El arreglo lo escribe el agente ahí."""
    a = leer(accion_id)
    if a["estado"] not in ("aprobada", "en-curso"):
        raise ValueError(f"{accion_id} está {a['estado']}: falta el OK del dueño (bin/hackme acciones aprobar {accion_id})")
    destino = TRABAJO / accion_id
    if not (destino / ".git").is_dir():
        if destino.exists():
            shutil.rmtree(destino)
        TRABAJO.mkdir(parents=True, exist_ok=True)
        subprocess.run(["gh", "repo", "clone", a["repo"], str(destino), "--", "--branch", a["base"], "--depth", "50"],
                       check=True, capture_output=True, text=True, timeout=600)
    subprocess.run(["git", "-C", str(destino), "checkout", "-q", "-B", a["rama"]], check=True, capture_output=True, text=True)
    if a["estado"] == "aprobada":
        _paso(a, "en-curso", carpeta=str(destino))
    return destino


def cerrar(accion_id, pr):
    a = leer(accion_id)
    if a["estado"] != "en-curso":
        raise ValueError(f"{accion_id} está {a['estado']}: primero bin/hackme acciones preparar {accion_id}")
    m = PR.match(pr or "")
    if not m or m.group(1).lower() != a["repo"].lower():
        raise ValueError(f"la URL no es un PR de {a['repo']}")
    dato = json.loads(subprocess.run(["gh", "pr", "view", pr, "--json", "headRefName,baseRefName,state"],
                                     check=True, capture_output=True, text=True, timeout=60).stdout)
    if dato["headRefName"] != a["rama"]:
        raise ValueError(f"ese PR sale de {dato['headRefName']}, no de {a['rama']}")
    a["pr"] = pr
    return _paso(a, "ejecutada", pr=pr)


def linea(a):
    return f"{a['id']:28} {a['estado']:10} {a['severidad']:8} {a['repo']}: {a['titulo']}" + (f"  {a['pr']}" if a.get("pr") else "")


def resumen():
    lista = todas()
    if not lista:
        return "acciones: ninguna"
    cuenta = {}
    for a in lista:
        cuenta[a["estado"]] = cuenta.get(a["estado"], 0) + 1
    return "\n".join([f"acciones: {cuenta}"] + ["  " + linea(a) for a in lista])
