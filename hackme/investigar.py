"""Investigar: de pista a hallazgo, con evidencia.

Lo que dice un escáner o un modelo es una pista, no un hallazgo. Este módulo abre una
investigación por cada pista seria de la ronda y junta la evidencia que se puede juntar sin
ejecutar nada: qué código cita la pista y si ese código sigue igual en la rama principal, en qué
commit. Después el agente (skill, paso 4d) lee ese código, suma lo que vio y decide. Solo una
investigación confirmada puede proponer una acción (acciones.py).

Cada evidencia dice de qué tipo es, para que nadie afirme más de lo que se probó:

  observado    se vio directo: tal archivo, en tal commit, dice esto
  deducido     se concluye de otra cosa: lo afirma un escáner, se infiere de una configuración
  sin-probar   lo que habría que ejecutar para saberlo, y no se ejecutó

Estados: pista -> confirmada | descartada | bloqueada. `arreglada` cuando la fuente deja de
reportarla. Una investigación cerrada se reabre sola si cambia el código que citaba.

Se guarda en $HACKME_PRIVADO/investigaciones/<id>.json. Solo lee: el código se pide a GitHub con
`gh api` (GET), nunca se ejecuta y nunca se prueba nada contra un sistema.
"""
import datetime
import fnmatch
import hashlib
import json
import re
import shutil
import subprocess

from . import rutas

CARPETA = rutas.PRIVADO / "investigaciones"
SEVERIDADES = ("crítica", "alta")   # de ahí para arriba se investiga
TOPE = 12                           # pistas nuevas por ronda: cada una son varias llamadas
ESTADOS = ("pista", "confirmada", "descartada", "bloqueada", "arreglada")
TIPOS = ("observado", "deducido", "sin-probar")
CERRADAS = ("confirmada", "descartada")

# ```ts title="ruta/archivo.ts:10-14"  (así cita Vercel Security Review)
CITA = re.compile(r"```[\w+-]*[ \t]+title=\"([^\"\n]+?):(\d+)(?:-(\d+))?\"[ \t]*\n(.*?)```", re.S)


def _ahora():
    return datetime.datetime.now().isoformat(timespec="minutes")


def _correr(cmd, espera=120):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=espera)
    if r.returncode != 0:
        raise RuntimeError((r.stderr.strip().splitlines() or [f"exit {r.returncode}"])[-1][:200])
    return r.stdout


def _es_secreto(ruta):
    nombre = ruta.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(nombre, patron) for patron in rutas.SECRETOS)


def _lineas(texto):
    return [" ".join(l.split()) for l in texto.splitlines() if l.strip()]


def citas_de(descripcion):
    """Las citas de código de una pista: [{archivo, desde, hasta, sello, _codigo}]."""
    salida = []
    for archivo, desde, hasta, codigo in CITA.findall(descripcion or ""):
        lineas = _lineas(codigo)
        if lineas:
            salida.append({"archivo": archivo, "desde": int(desde), "hasta": int(hasta or desde),
                           "sello": hashlib.sha256("\n".join(lineas).encode()).hexdigest()[:16], "_codigo": lineas})
    return salida


def buscar(lineas, archivo_texto):
    """En qué línea del archivo aparece el bloque citado (ignorando espacios), o None si ya no está."""
    todas = [(n, " ".join(l.split())) for n, l in enumerate(archivo_texto.splitlines(), 1) if l.strip()]
    for i in range(len(todas) - len(lineas) + 1):
        if all(todas[i + k][1] == lineas[k] for k in range(len(lineas))):
            return todas[i][0]
    return None


def leer_github(repo, rama, archivo):
    """El archivo tal como está hoy en la rama, y el commit. Solo GET."""
    sha = _correr(["gh", "api", f"repos/{repo}/commits/{rama}", "--jq", ".sha"]).strip()
    texto = _correr(["gh", "api", "-H", "Accept: application/vnd.github.raw", f"repos/{repo}/contents/{archivo}?ref={sha}"])
    return texto, sha


def detalle_review(slug, hallazgo_id):
    """La vulnerabilidad completa de Vercel Security Review. `inspect` solo lee."""
    salida = _correr(["vercel", "security", "vulnerabilities", "inspect", hallazgo_id, "--json", "--non-interactive", "--scope", slug])
    return json.loads(salida).get("vulnerability") or {}


def _evidencia(tipo, que, donde="", quien="hackme"):
    return {"tipo": tipo, "que": que, "donde": donde, "cuando": _ahora(), "quien": quien}


def verificar_citas(inv):
    """Revisa contra GitHub si el código citado sigue igual. Devuelve la evidencia automática."""
    evidencia, cache = [], {}
    for c in inv["citas"]:
        if _es_secreto(c["archivo"]):
            c["codigo"] = "sin-leer"
            evidencia.append(_evidencia("sin-probar", "la pista cita un archivo de secretos: no se abre", c["archivo"]))
            continue
        try:
            if c["archivo"] not in cache:
                cache[c["archivo"]] = leer_github(inv["repo"], inv["rama"], c["archivo"])
            texto, sha = cache[c["archivo"]]
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
            c["codigo"] = "sin-leer"
            evidencia.append(_evidencia("sin-probar", f"no se pudo leer el archivo citado: {e}", c["archivo"]))
            continue
        linea = buscar(c["_codigo"], texto)
        c["visto_en"] = sha[:12]
        if linea:
            c["codigo"] = "sigue"
            evidencia.append(_evidencia("observado", "el código citado sigue igual en la rama principal",
                                        f"{c['archivo']}:{linea} @ {inv['rama']} {sha[:12]}"))
        else:
            c["codigo"] = "cambió"
            evidencia.append(_evidencia("observado", "el código citado ya no está igual en la rama principal: hay que mirarlo de nuevo",
                                        f"{c['archivo']} @ {inv['rama']} {sha[:12]}"))
    return evidencia


def _archivo(inv_id):
    return CARPETA / f"{inv_id}.json"


def leer(inv_id):
    return json.loads(_archivo(inv_id).read_text())


def guardar(inv):
    CARPETA.mkdir(parents=True, exist_ok=True)
    limpio = {**inv, "citas": [{k: v for k, v in c.items() if not k.startswith("_")} for c in inv.get("citas", [])]}
    limpio["actualizada"] = _ahora()
    _archivo(inv["id"]).write_text(json.dumps(limpio, ensure_ascii=False, indent=1))


def todas():
    return [json.loads(p.read_text()) for p in sorted(CARPETA.glob("*.json"))] if CARPETA.is_dir() else []


def _abrir(h, detalle):
    slug, hallazgo_id = h["id"].split(":")[1], h["id"].rsplit(":", 1)[-1]
    inv = {
        "id": "review-" + hallazgo_id[-10:].lower(), "fuente": "vercel-security-review", "origen": h["id"],
        "repo": h["recurso"], "rama": detalle.get("branchRef") or (h.get("detalle") or {}).get("rama") or "main",
        "titulo": detalle.get("title") or h["titulo"], "severidad": h["severidad"], "clase": detalle.get("vulnerabilityClass"),
        "afirmacion": detalle.get("summary") or "", "arreglo_sugerido": detalle.get("fix") or "",
        "estado": "pista", "evidencia": [], "citas": citas_de(detalle.get("description")), "notas": [],
        "proxima": "leer el código citado y decidir: confirmada, descartada o bloqueada",
        "reabrir_si": "cambia el código citado", "creada": _ahora(),
    }
    inv["evidencia"].append(_evidencia(
        "deducido", f"Vercel Security Review lo marca como {inv['clase']} ({inv['severidad']}); es la lectura de un modelo, no una prueba",
        f"vercel security vulnerabilities inspect {hallazgo_id} --scope {slug}"))
    return inv


def refrescar(inv, detalle):
    """Vuelve a juntar la evidencia automática. Lo que anotó el agente no se toca."""
    inv["citas"] = citas_de(detalle.get("description"))
    propia = [e for e in inv["evidencia"] if e.get("quien") != "hackme" or e["tipo"] == "deducido"]
    inv["evidencia"] = propia + verificar_citas(inv) + [_evidencia(
        "sin-probar", "que se pueda explotar de verdad: no se ejecutó nada, ni en una copia ni en producción")]
    if inv["estado"] in CERRADAS and any(c.get("codigo") == "cambió" for c in inv["citas"]):
        inv["notas"].append(f"{_ahora()}: reabierta, estaba {inv['estado']} y cambió el código citado")
        inv["estado"] = "pista"
    return inv


def correr(ronda):
    """Abre o refresca una investigación por cada pista seria de la ronda."""
    vercel = ronda.get("vercel") or {}
    pistas = [h for h in vercel.get("hallazgos", []) if ":review:" in h["id"] and h["severidad"] in SEVERIDADES]
    orden = {s: i for i, s in enumerate(SEVERIDADES)}
    pistas.sort(key=lambda h: orden[h["severidad"]])
    existentes = {i["origen"]: i for i in todas()}
    salida = {"nuevas": [], "reabiertas": [], "arregladas": [], "errores": {}, "abiertas": []}
    hay_herramientas = bool(shutil.which("vercel") and shutil.which("gh"))
    nuevas = 0
    for h in pistas:
        inv = existentes.get(h["id"])
        if not inv and nuevas >= TOPE:
            continue
        if not hay_herramientas:
            salida["errores"][h["id"]] = "faltan el CLI de vercel o gh: no se puede juntar la evidencia"
            continue
        try:
            detalle = detalle_review(h["id"].split(":")[1], h["id"].rsplit(":", 1)[-1])
        except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as e:
            salida["errores"][h["id"]] = str(e)[:200]
            continue
        if not inv:
            inv, nuevas = _abrir(h, detalle), nuevas + 1
            salida["nuevas"].append(inv["id"])
        estaba = inv["estado"]
        refrescar(inv, detalle)
        if estaba in CERRADAS and inv["estado"] == "pista":
            salida["reabiertas"].append(inv["id"])
        guardar(inv)
    # Lo que la fuente dejó de listar como abierto: se le pregunta a la fuente antes de darlo por arreglado.
    vivas = {h["id"] for h in vercel.get("hallazgos", []) if ":review:" in h["id"]}
    for origen, inv in existentes.items():
        if origen in vivas or inv["estado"] == "arreglada" or not hay_herramientas:
            continue
        try:
            detalle = detalle_review(origen.split(":")[1], origen.rsplit(":", 1)[-1])
        except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired):
            continue   # si la fuente no contesta, no se concluye nada
        if detalle.get("status") and detalle["status"] != "open":
            inv["evidencia"].append(_evidencia("observado", f"la fuente la da por {detalle['status']}",
                                               f"vercel security vulnerabilities inspect {origen.rsplit(':', 1)[-1]}"))
            inv["notas"].append(f"{_ahora()}: {inv['estado']} -> arreglada")
            inv["estado"] = "arreglada"
            guardar(inv)
            salida["arregladas"].append(inv["id"])
    salida["abiertas"] = [{k: i.get(k) for k in ("id", "repo", "severidad", "estado", "titulo", "proxima")}
                          for i in todas() if i["estado"] != "arreglada"]
    return salida


def anotar(inv_id, estado=None, tipo=None, que=None, donde="", proxima=None):
    """Lo que suma el agente después de leer: una evidencia, un cambio de estado o las dos cosas."""
    inv = leer(inv_id)
    if tipo or que:
        if tipo not in TIPOS or not que:
            raise ValueError(f"una evidencia lleva --tipo ({', '.join(TIPOS)}) y --que")
        inv["evidencia"].append(_evidencia(tipo, que, donde, quien="agente"))
    if estado:
        if estado not in ESTADOS:
            raise ValueError(f"estado desconocido: {estado} (van: {', '.join(ESTADOS)})")
        vio = any(e["tipo"] == "observado" and e.get("quien") == "agente" for e in inv["evidencia"])
        if estado == "confirmada" and not vio:
            raise ValueError("para confirmar hace falta al menos una evidencia observada por el agente: leé el código y anotá qué viste")
        if estado in ("descartada", "bloqueada") and not any(e.get("quien") == "agente" for e in inv["evidencia"]):
            raise ValueError(f"para marcarla {estado} anotá por qué (--tipo y --que)")
        inv["notas"].append(f"{_ahora()}: {inv['estado']} -> {estado}")
        inv["estado"] = estado
    if proxima:
        inv["proxima"] = proxima
    guardar(inv)
    return inv


def ficha(inv):
    """La investigación en texto, para leerla sin abrir el JSON."""
    lineas = [f"{inv['id']} · {inv['estado'].upper()} · {inv['severidad']} · {inv['repo']}", inv["titulo"], "", inv.get("afirmacion", ""), "", "Evidencia:"]
    for e in inv["evidencia"]:
        lineas.append(f"  [{e['tipo']:10}] {e['que']}" + (f"  ({e['donde']})" if e.get("donde") else "") + f"  — {e.get('quien', '?')}")
    if inv.get("arreglo_sugerido"):
        lineas += ["", "Arreglo que sugiere la fuente:", "  " + inv["arreglo_sugerido"]]
    lineas += ["", f"Próximo paso: {inv.get('proxima', '')}", f"Se reabre si: {inv.get('reabrir_si', '')}"]
    return "\n".join(lineas)


def resumen(r):
    por_estado = {}
    for i in r["abiertas"]:
        por_estado[i["estado"]] = por_estado.get(i["estado"], 0) + 1
    return (f"investigaciones: {len(r['abiertas'])} abiertas {por_estado or ''}, {len(r['nuevas'])} nuevas, "
            f"{len(r['reabiertas'])} reabiertas, {len(r['arregladas'])} arregladas"
            + "".join(f"  ERROR {k.rsplit(':', 1)[-1][:10]}: {v[:80]}" for k, v in r["errores"].items()))
