"""Aguara sobre todos los repos y la Mac.

Dos pasadas por repo, porque `aguara audit` (que las junta) ignora a propósito las
exclusiones del repo y se traba con los cachés gigantes de `.next/`:

  - `aguara scan` sobre el espejo: una copia liviana sin dependencias instaladas, builds
    ni medios (ver rutas.EXCLUIR_ESPEJO). Prompt injection, credenciales, exfiltración,
    MCP y workflows. Con --monitor detecta skills que cambian de una corrida a la otra.
  - `aguara check` sobre el repo real: paquetes comprometidos en lockfiles y entornos.

Cada hallazgo se marca "nuevo" si no estaba en la corrida anterior.
"""
import hashlib
import json
import re
import subprocess

from . import rutas

SEVERIDAD = {4: "crítica", 3: "alta", 2: "media", 1: "baja", 0: "info"}


def _json(args):
    try:
        salida = subprocess.run(args, capture_output=True, text=True, timeout=900).stdout
        return json.loads(salida) if salida.strip() else {"error": "sin salida"}
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    except ValueError:
        return {"error": salida[-300:]}


def espejar():
    rutas.ESPEJO.mkdir(parents=True, exist_ok=True)
    # En rsync gana la primera regla que coincide: los include van antes que los exclude.
    filtros = ([f"--include={x}" for x in rutas.INCLUIR_ESPEJO] + [f"--exclude={x}" for x in rutas.EXCLUIR_ESPEJO]
               + [f"--exclude=/{x}" for x in rutas.PROPIOS])
    subprocess.run(["rsync", "-a", "--delete", "--delete-excluded", f"--max-size={rutas.TAMANO_MAXIMO}",
                    *filtros, f"{rutas.GITHUB}/", f"{rutas.ESPEJO}/"], check=True, capture_output=True)


def secretos_versionados(repo):
    """Archivos con pinta de secreto que git trackea. Solo nombres; no se abre ninguno."""
    carpeta = rutas.GITHUB / repo
    if not (carpeta / ".git").exists():
        return []
    salida = subprocess.run(["git", "-C", str(carpeta), "ls-files", "--", *rutas.SECRETOS,
                             *[f"**/{p}" for p in rutas.SECRETOS]], capture_output=True, text=True).stdout
    return sorted({a for a in salida.splitlines() if not a.endswith(".env.example")})


# Dónde un hallazgo de Aguara importa de verdad: lo que leen y ejecutan los agentes.
# En el resto del código de las apps las reglas de Aguara dan mucho falso positivo.
# Ojo con "hooks/" o "agents/" sueltos: en una app React o en fixtures no son de agentes.
SUPERFICIE_AGENTICA = re.compile(
    r"(^|/)(\.claude|\.cursor|\.codex|\.agents|\.github|skills|plugin|prompts)/"
    r"|(^|/)(CLAUDE|AGENTS|GEMINI|SKILL)\.md$|(^|/)\.?mcp[\w.-]*\.json$|\.mdc$|(^|/)\.cursorrules$")


def _capa(h):
    if SUPERFICIE_AGENTICA.search(h["archivo"]):
        return "agéntica"
    if h["regla"].startswith("CRED_") and h["severidad"] == "crítica":
        return "credencial"
    return "código"


def _clave(repo, f):
    linea = next((c["content"] for c in f.get("context", []) if c.get("is_match")), "")
    return hashlib.sha1(f"{repo}|{f['rule_id']}|{f['file_path']}|{linea}".encode()).hexdigest()[:16]


def correr():
    espejar()
    rutas.MEMORIA.mkdir(parents=True, exist_ok=True)
    previo_p = rutas.MEMORIA / "aguara-previo.json"
    previo = set(json.loads(previo_p.read_text())) if previo_p.exists() else None
    monitor = rutas.MEMORIA / "aguara-monitor"
    monitor.mkdir(parents=True, exist_ok=True)
    comun = ["--format", "json", "--no-update-check"]

    repos, claves = {}, []
    for repo in (p.name for p in rutas.repos()):
        carpeta = rutas.ESPEJO / repo
        if not carpeta.is_dir():
            continue
        scan = _json([rutas.AGUARA, "scan", str(carpeta), *comun, "--project-policy", "ignore",
                      "--severity", "medium", "--monitor", "--state-path", str(monitor / f"{repo}.json")])
        check = _json([rutas.AGUARA, "check", str(rutas.GITHUB / repo), *comun])
        hallazgos = []
        for f in scan.get("findings", []):
            k = _clave(repo, f)
            claves.append(k)
            hallazgos.append({
                "regla": f["rule_id"], "nombre": f["rule_name"], "severidad": SEVERIDAD.get(f["severity"], f["severity"]),
                "categoria": f["category"], "archivo": f["file_path"], "linea": f.get("line"),
                "impacto": f.get("decision_impact"), "arreglo": f.get("remediation"),
                "nuevo": previo is not None and k not in previo,
            })
            hallazgos[-1]["capa"] = _capa(hallazgos[-1])
        repos[repo] = {
            "secretos_versionados": secretos_versionados(repo),
            "veredicto": scan.get("verdict"), "riesgo": round(scan.get("risk_score") or 0, 1),
            "archivos": scan.get("files_scanned"), "error_scan": scan.get("error"),
            "hallazgos": hallazgos,
            "paquetes_leidos": check.get("packages_read"), "error_check": check.get("error"),
            "paquetes_comprometidos": check.get("findings") or [],
            "artefactos": check.get("credentials") or [],
        }

    # La Mac: configs de clientes MCP y los paquetes npm globales. En la nube no hay Mac.
    mac = {"mcp_clientes": {}, "npm_global": {}}
    if rutas.MODO != "nube":
        npm_root = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True).stdout.strip()
        mac = {
            "mcp_clientes": _json([rutas.AGUARA, "scan", "--auto", *comun, "--severity", "medium"]),
            "npm_global": _json([rutas.AGUARA, "check", npm_root, *comun]) if npm_root else {},
        }
    for f in mac["mcp_clientes"].get("findings", []):
        f.pop("context", None)  # puede traer líneas de configs con tokens; ya viene redactado igual

    resultado = {"repos": repos, "mac": mac, "primera_corrida": previo is None}
    (rutas.ESTADO / "aguara.json").write_text(json.dumps(resultado, ensure_ascii=False, indent=1))
    previo_p.write_text(json.dumps(sorted(set(claves))))
    return resultado


def resumen(r):
    def altos(x, capa):
        return [h for h in x["hallazgos"] if h["capa"] == capa and h["severidad"] in ("crítica", "alta")]

    total = sum(len(x["hallazgos"]) for x in r["repos"].values())
    nuevos = sum(1 for x in r["repos"].values() for h in x["hallazgos"] if h["nuevo"])
    comprometidos = sum(len(x["paquetes_comprometidos"]) for x in r["repos"].values())
    lineas = [f"aguara: {len(r['repos'])} repos, {total} hallazgos ({nuevos} nuevos), "
              f"{comprometidos} paquetes comprometidos"]
    for repo, x in sorted(r["repos"].items()):
        ag, cr = altos(x, "agéntica"), altos(x, "credencial")
        if ag or cr or x["paquetes_comprometidos"] or x["secretos_versionados"] or x["error_scan"] or x["error_check"]:
            lineas.append(f"  {repo:28} agénticos {len(ag):3}  credenciales {len(cr):3}  paquetes {len(x['paquetes_comprometidos'])}"
                          f"  secretos en git {len(x['secretos_versionados'])}"
                          + (f"  ERROR scan: {x['error_scan'][:80]}" if x["error_scan"] else "")
                          + (f"  ERROR check: {x['error_check'][:80]}" if x["error_check"] else ""))
    mcp = r["mac"]["mcp_clientes"]
    lineas.append(f"  Mac: MCP {len(mcp.get('findings', []))} hallazgos; npm global "
                  f"{len(r['mac']['npm_global'].get('findings') or [])} comprometidos")
    return "\n".join(lineas)
