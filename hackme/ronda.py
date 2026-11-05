"""La ronda completa: inventario (ya hecho por quien llama) -> Aguara -> Radar.

Aguara va primero porque arma el espejo, y Radar lo usa para buscar menciones de
proveedores en la documentación de los repos. Deja todo junto en estado/ronda.json para
que el agente de la tarea programada lo lea de un solo archivo.
"""
import datetime
import json

from . import aguara, aws, caminos, radar, rutas, vercel


def correr(inv):
    ag = aguara.correr()
    rd = radar.correr(inv)
    nube_aws = aws.correr()
    vc = vercel.correr()

    def importa(h):
        return h["capa"] in ("agéntica", "credencial") and h["severidad"] in ("crítica", "alta")

    ronda = {
        "fecha": datetime.datetime.now().isoformat(timespec="minutes"),
        "modo": rutas.MODO,
        "primera_corrida": ag["primera_corrida"],
        "radar": rd,
        "aguara": {
            "nuevos": [{"repo": r, **h} for r, x in ag["repos"].items() for h in x["hallazgos"] if h["nuevo"]],
            "importantes": [{"repo": r, **h} for r, x in ag["repos"].items() for h in x["hallazgos"] if importa(h)],
            "paquetes_comprometidos": {r: x["paquetes_comprometidos"] for r, x in ag["repos"].items() if x["paquetes_comprometidos"]},
            "secretos_versionados": {r: x["secretos_versionados"] for r, x in ag["repos"].items() if x["secretos_versionados"]},
            "errores": {r: x["error_scan"] or x["error_check"] for r, x in ag["repos"].items() if x["error_scan"] or x["error_check"]},
            "mac": ag["mac"],
            "por_repo": {r: {"riesgo": x["riesgo"], "hallazgos": len(x["hallazgos"])} for r, x in ag["repos"].items()},
        },
        "aws": nube_aws,
        "vercel": vc,
    }
    # Al final: los caminos de ataque se arman con lo que juntaron todas las fuentes.
    ronda["caminos"] = caminos.correr(ronda)
    (rutas.ESTADO / "ronda.json").write_text(json.dumps(ronda, ensure_ascii=False, indent=1))
    return "\n".join([radar.resumen(rd), aguara.resumen(ag), aws.resumen(nube_aws), vercel.resumen(vc),
                      caminos.resumen(ronda["caminos"]), f"-> {rutas.ESTADO / 'ronda.json'}"])
