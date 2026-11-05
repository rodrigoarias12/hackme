"""Qué ya vio cada fuente, para marcar cada hallazgo como nuevo, actualizado o visto.

Cada fuente guarda {id: sello} en memoria/<modo>/<fuente>-visto.json. El sello es lo que, si
cambia, vuelve a hacer relevante al hallazgo (una fecha de actualización, un conteo, un rol).
La primera vez que corre una fuente todo es "línea de base": se registra y no se avisa.
"""
import json

from . import rutas


def marcar(fuente, hallazgos, sellar=lambda h: h.get("detalle")):
    rutas.MEMORIA.mkdir(parents=True, exist_ok=True)
    archivo = rutas.MEMORIA / f"{fuente}-visto.json"
    primera = not archivo.exists()
    visto = {} if primera else json.loads(archivo.read_text())
    for h in hallazgos:
        sello = json.dumps(sellar(h), sort_keys=True, ensure_ascii=False, default=str)
        if primera:
            h["estado"] = "línea de base"
        elif h["id"] not in visto:
            h["estado"] = "nuevo"
        else:
            h["estado"] = "actualizado" if visto[h["id"]] != sello else "visto"
        visto[h["id"]] = sello
    archivo.write_text(json.dumps(visto, indent=0, sort_keys=True, ensure_ascii=False))
    return primera
