# CLAUDE.md — Centinela

Agente de seguridad transversal. Mira todos los repos de `~/Documents/GitHub` y la Mac,
los cruza contra [Oktsec Radar](https://www.oktsec.com/radar), los escanea con
[Aguara](https://github.com/garagon/aguara) y lee lo que encontraron los escáneres de AWS
(GuardDuty, Security Hub, Inspector). Avisa; no bloquea.

## Dos repos

- **Este (`centinela`)**: el código. Puede ser público. Acá no se escribe ningún hallazgo,
  informe, nombre de repo afectado ni dato de una cuenta.
- **`centinela-privado`** (`CENTINELA_PRIVADO`, por defecto `~/Documents/GitHub/centinela-privado`):
  informes, memoria entre rondas (avisos vistos, hallazgos previos) y alertas. Siempre privado.

## Reglas para agentes

1. **Solo observa.** Centinela nunca modifica, borra ni "limpia" nada fuera de sus dos repos.
   Nada de `aguara clean`, `npm uninstall`, editar otros repos ni cambiar nada en AWS (ni
   archivar hallazgos). Si algo hay que arreglar, se propone en el informe.
2. **Nunca bloquea.** No activa enforce en oktsec ni agrega hooks que corten tool calls.
3. **Secretos.** Nunca leer `.env` reales ni imprimir valores de credenciales. El espejo excluye
   los archivos de secretos (`rutas.SECRETOS`) y de los versionados en git solo se mira el
   nombre. Los hallazgos de Aguara vienen redactados: no se usa `--no-redact`.
4. **Hacia afuera, solo lo autorizado.** Telegram (`bin/avisar`), notificación local o un issue
   en `centinela-privado`. Abrir issues en los repos revisados está **apagado**
   (`ABRIR_ISSUES` en `centinela/rutas.py`).
5. **Radar no prueba nada.** Que un aviso coincida con el inventario no significa que estés
   afectado, y que no coincida no significa que estés a salvo. Comparar versiones contra el
   rango del aviso y linkear la fuente.

## Cómo correr

```bash
bin/centinela ronda        # inventario + Aguara + Radar + AWS -> estado/ronda.json
bin/centinela inventario   # solo el inventario
bin/centinela radar        # solo bajar Radar y cruzar (usa el último inventario)
bin/centinela aguara       # solo el escaneo de repos
bin/avisar "mensaje"       # aviso por Telegram (sale 2 si no está configurado)
```

`CENTINELA_MODO`: `todo` (por defecto), `nube` (rutina en la nube: repos clonados, sin Mac) o
`mac` (tarea local: la Mac y las carpetas sin remoto). La parte agente (juzgar candidatos,
escribir el informe, avisar) está en [tarea/SKILL.md](tarea/SKILL.md).
