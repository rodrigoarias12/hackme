"""Hallazgos de los escáneres de AWS: GuardDuty, Security Hub e Inspector.

AWS escanea; hackme solo lee lo que encontraron y marca qué es nuevo desde la ronda
anterior. Todo es lectura (get/list): nunca archiva, suprime ni cambia nada en la cuenta.

Perfiles: HACKME_AWS="perfil:region,perfil:region" (por defecto "default:us-east-1").
En la nube, sin perfiles, usa las variables AWS_* del ambiente si existen.
"""
import json
import os
import shutil
import subprocess

from . import rutas


def _aws(perfil, region, *args):
    env = dict(os.environ, AWS_REGION=region, AWS_PAGER="")
    if perfil:
        env["AWS_PROFILE"] = perfil
    r = subprocess.run(["aws", *args, "--output", "json"], capture_output=True, text=True, timeout=120, env=env)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip().splitlines()[-1] if r.stderr.strip() else f"exit {r.returncode}")
    return json.loads(r.stdout or "{}")


def _ips(o, acc):
    if isinstance(o, dict):
        for k, v in o.items():
            if k == "IpAddressV4" and isinstance(v, str):
                acc["ips"].add(v)
            elif k == "Country" and isinstance(v, dict) and v.get("CountryName"):
                acc["origen"].add(v["CountryName"])
            elif k == "Organization" and isinstance(v, dict) and v.get("AsnOrg"):
                acc["origen"].add(v["AsnOrg"])
            _ips(v, acc)
    elif isinstance(o, list):
        for x in o:
            _ips(x, acc)


def guardduty(perfil, region):
    salida = []
    for detector in _aws(perfil, region, "guardduty", "list-detectors").get("DetectorIds", []):
        criterio = json.dumps({"Criterion": {"service.archived": {"Eq": ["false"]}, "severity": {"Gte": 4}}})
        ids = _aws(perfil, region, "guardduty", "list-findings", "--detector-id", detector,
                   "--finding-criteria", criterio).get("FindingIds", [])
        for i in range(0, len(ids), 50):
            for f in _aws(perfil, region, "guardduty", "get-findings", "--detector-id", detector,
                          "--finding-ids", *ids[i:i + 50]).get("Findings", []):
                s, acc = f.get("Service", {}), {"ips": set(), "origen": set()}
                _ips(s.get("Action", {}), acc)
                salida.append({
                    "id": f["Id"], "servicio": "GuardDuty", "severidad": f["Severity"], "tipo": f["Type"],
                    "titulo": f["Title"], "recurso": f.get("Resource", {}).get("ResourceType"),
                    "primera": s.get("EventFirstSeen"), "ultima": s.get("EventLastSeen"), "veces": s.get("Count"),
                    "ips": sorted(acc["ips"]), "origen": sorted(acc["origen"]), "actualizado": f.get("UpdatedAt"),
                })
    return salida


def securityhub(perfil, region):
    filtros = json.dumps({
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [{"Value": v, "Comparison": "EQUALS"} for v in ("NEW", "NOTIFIED")],
        "SeverityLabel": [{"Value": v, "Comparison": "EQUALS"} for v in ("CRITICAL", "HIGH")],
        # Lo de GuardDuty e Inspector ya viene por su lado, con más detalle.
        "ProductName": [{"Value": p, "Comparison": "NOT_EQUALS"} for p in ("GuardDuty", "Inspector")],
    })
    return [{
        "id": f["Id"], "servicio": "Security Hub", "severidad": f["Severity"]["Label"], "titulo": f["Title"],
        "recurso": ", ".join(r.get("Id", "").split(":")[-1] for r in f.get("Resources", [])[:3]),
        "control": (f.get("Compliance") or {}).get("SecurityControlId"), "actualizado": f.get("UpdatedAt"),
        "arreglo": (f.get("Remediation") or {}).get("Recommendation", {}).get("Url"),
    } for f in _aws(perfil, region, "securityhub", "get-findings", "--filters", filtros, "--max-items", "200").get("Findings", [])]


def inspector(perfil, region):
    criterio = json.dumps({"findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
                           "severity": [{"comparison": "EQUALS", "value": v} for v in ("CRITICAL", "HIGH")]})
    salida = []
    for f in _aws(perfil, region, "inspector2", "list-findings", "--filter-criteria", criterio, "--max-items", "200").get("findings", []):
        vuln = f.get("packageVulnerabilityDetails") or {}
        salida.append({
            "id": f["findingArn"], "servicio": "Inspector", "severidad": f["severity"], "titulo": f["title"],
            "recurso": ", ".join(r.get("id", "").split("/")[-1] for r in f.get("resources", [])[:3]),
            "cve": vuln.get("vulnerabilityId"), "arreglo_disponible": f.get("fixAvailable"),
            "paquetes": [f"{p.get('name')} {p.get('version')} -> {p.get('fixedInVersion')}"
                         for p in vuln.get("vulnerablePackages", [])[:3]],
            "actualizado": f.get("updatedAt"),
        })
    return salida


def correr():
    if not shutil.which("aws"):
        return {"cuentas": [], "error": "no está el CLI de AWS"}
    perfiles = os.environ.get("HACKME_AWS", "default:us-east-1" if rutas.MODO != "nube" else ":us-east-1")
    rutas.MEMORIA.mkdir(parents=True, exist_ok=True)
    visto_p = rutas.MEMORIA / "aws-visto.json"
    visto = json.loads(visto_p.read_text()) if visto_p.exists() else {}
    primera = not visto_p.exists()

    cuentas = []
    for par in filter(None, perfiles.split(",")):
        perfil, _, region = par.partition(":")
        cuenta = {"perfil": perfil or "(ambiente)", "region": region, "hallazgos": [], "errores": {}}
        try:
            cuenta["cuenta"] = _aws(perfil, region, "sts", "get-caller-identity").get("Account")
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as e:
            cuenta["errores"]["credenciales"] = str(e)  # p. ej. "Your session has expired"
            cuentas.append(cuenta)
            continue
        for nombre, fn in (("guardduty", guardduty), ("securityhub", securityhub), ("inspector", inspector)):
            try:
                cuenta["hallazgos"] += fn(perfil, region)
            except (RuntimeError, ValueError, subprocess.TimeoutExpired) as e:
                cuenta["errores"][nombre] = str(e)
        for h in cuenta["hallazgos"]:
            h["estado"] = "visto" if visto.get(h["id"]) == h["actualizado"] else (
                "actualizado" if h["id"] in visto else "nuevo")
            if primera:
                h["estado"] = "línea de base"
            visto[h["id"]] = h["actualizado"]
        cuentas.append(cuenta)

    visto_p.write_text(json.dumps(visto, indent=1))
    return {"cuentas": cuentas, "primera_corrida": primera}


def resumen(r):
    if r.get("error"):
        return f"aws: {r['error']}"
    lineas = []
    for c in r["cuentas"]:
        nuevos = sum(h["estado"] in ("nuevo", "actualizado") for h in c["hallazgos"])
        lineas.append(f"aws {c['perfil']} ({c.get('cuenta', '?')}, {c['region']}): {len(c['hallazgos'])} hallazgos, {nuevos} nuevos"
                      + "".join(f"  ERROR {k}: {v[:80]}" for k, v in c["errores"].items()))
    return "\n".join(lineas)
