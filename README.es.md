# hackme

[English](README.md)
<p align="center"><img src="docs/img/banner-es.svg" alt="hackme: un agente de seguridad que solo mira y avisa" width="100%"></p>

Un agente de seguridad que mira **todo lo que corrés**: tus repos, tu Mac, tu cuenta de AWS y tus
equipos de Vercel. Todos los días cruza los avisos de [Oktsec Radar](https://www.oktsec.com/radar)
con tu inventario real, le pasa [Aguara](https://github.com/garagon/aguara) a cada repo, lee lo
que encontraron GuardDuty, Security Hub e Inspector, revisa tus equipos y proyectos de Vercel, y
te avisa por Telegram solo lo nuevo que te toca.

Cada 15 minutos, el **vigía** mira lo que está pasando ahora: alguien barriendo tus rutas,
probando logins, usando la cuenta root de AWS, apagando logs. Te avisa por Telegram mientras pasa.

No bloquea ni arregla nada: mira, compara y avisa. Los arreglos van al informe como propuestas
para una persona.

- [Cómo funciona](#cómo-funciona)
- [Qué mira](#qué-mira)
- [Vigía: la guardia de 15 minutos](#vigía-la-guardia-de-15-minutos)
- [Instalar](#instalar)
- [Que corra todos los días](#que-corra-todos-los-días)
- [Telegram](#telegram)
- [Configuración](#configuración)
- [Comandos](#comandos)
- [Dónde vive cada cosa](#dónde-vive-cada-cosa)
- [Reglas de base](#reglas-de-base)
- [Límites](#límites)
- [Lo que viene](#lo-que-viene)

## Cómo funciona

<p align="center"><img src="docs/img/flujo-es.svg" alt="Cómo funciona hackme: la ronda diaria y el vigía de 15 minutos leen detrás de una frontera de solo lectura y avisan por Telegram" width="100%"></p>

```
bin/hackme ronda
  ├─ inventario   cada carpeta de ~/Documents/GitHub + la Mac
  │               (paquetes npm/PyPI/Go, imágenes Docker, Actions, configs MCP, servicios,
  │                apps, brew, extensiones de Cursor/VS Code, runtimes)
  ├─ aguara       espejo sin secretos → scan con --monitor
  │               + chequeo de paquetes comprometidos en el repo real
  │               + archivos de secretos versionados en git (solo nombres)
  ├─ radar        items.json de Radar × inventario → candidatos con fuerza de coincidencia
  │               (version-afectada / nombre / mencion)
  ├─ aws          hallazgos de GuardDuty, Security Hub e Inspector (solo lectura)
  └─ vercel       equipos, higiene de variables, previews, firewall, auditoría (solo lectura)
        ↓
  estado/ronda.json  (forma: docs/ronda.md)
        ↓
  el agente (skills/hackme/SKILL.md) juzga cada candidato, escribe el informe en un repo
  privado y te avisa por Telegram si hay algo nuevo
```

Dos capas a propósito:

- **El CLI** (`hackme/`, solo biblioteca estándar de Python) es determinístico: junta, cruza y
  recuerda lo que ya vio. Cruza de más a propósito; nunca decide "te afecta".
- **El skill** es donde el agente juzga: compara la versión instalada con el rango del aviso, lee
  la línea citada antes de decir que algo es real, descarta datos de prueba y escribe un informe
  corto y claro.

Cada fuente tiene memoria entre rondas (`nuevo` / `actualizado` / `visto` / `línea de base`): la
primera corrida es la línea de base y después solo aparece lo que cambió.

## Qué mira

| Fuente | Qué busca | Cómo |
|---|---|---|
| **Inventario** | Cada paquete, imagen, GitHub Action, servidor MCP, servicio y *nombre* de variable de tus repos; apps, brew, extensiones del editor, runtimes, npm global y configs MCP de la Mac | Lee manifiestos y lockfiles. Solo `.env.example`, nunca el `.env` real |
| **Oktsec Radar** | Avisos (vulnerabilidades, ataques a la cadena de suministro, brechas de plataformas, actividad de amenazas) que coinciden con algo que realmente usás | `items.json` × inventario; versiones afectadas exactas con datos de OSV cuando Radar los trae |
| **Aguara** | Prompt injection e instrucciones peligrosas en skills, `CLAUDE.md`/`AGENTS.md`, configs MCP y workflows; credenciales en el código; paquetes comprometidos; archivos de secretos versionados | `aguara scan --monitor` sobre un espejo sin secretos, `aguara check` sobre el repo real, `git ls-files` para nombres de archivos de secretos |
| **AWS** | Hallazgos de GuardDuty (severidad 4+), Security Hub HIGH/CRITICAL, Inspector HIGH/CRITICAL | AWS CLI con un perfil de solo lectura, uno o más pares `perfil:región` |
| **Vercel** | Pedidos de acceso pendientes y miembros nuevos; variables con nombre de secreto y prefijo público (llegan al navegador); secretos `plain`; secretos de producción también en `development` (cualquiera con `vercel env pull` se los lleva a su compu); secretos de producción no `sensitive`; previews sin protección y firewall apagado en proyectos con dominio propio; proyectos viejos publicados; eventos de auditoría (`env pull`, variables cambiadas, miembros, tokens, protección, firewall); el chequeo de seguridad del propio Vercel (miembros sin MFA, tokens que no vencen, demasiados owners) | API de Vercel con la sesión del CLI (`vercel api`) o `VERCEL_TOKEN`. De cada variable solo `key`, `type` y `target`, nunca el valor |

<p align="center"><img src="docs/img/detecciones-es.svg" alt="81 detecciones por familia: 37 funcionando, 8 a medias, 36 por armar" width="100%"></p>

La lista completa de detecciones, hechas y por hacer, basada en OWASP, MITRE ATT&CK y los
benchmarks de CIS, está en [docs/detecciones.md](docs/detecciones.md).

## Vigía: la guardia de 15 minutos

<p align="center"><img src="docs/img/ataque-es.svg" alt="Un escaneo a escala: una IP cruza el umbral a las 02:23 y el vigía avisa a las 02:30" width="100%"></p>

```
bin/hackme vigia               cada 15 min (launchd en la Mac)
  ├─ tus apps     SQL que escribís vos, solo lectura: accesos, logins, cuentas
  │               → barridos de rutas, escáneres, picos del firewall, spraying, logins
  │                 después de fallos, países nuevos, un log que se calló, cuentas dormidas
  └─ aws          eventos de escritura de CloudTrail + GuardDuty de cualquier severidad
                  → uso de root, login sin MFA, logs apagados, IAM, S3, KMS, red
        ↓
  Telegram, una vez por clave por día, máximo 25 por día
```

Determinístico, sin IA. Cómo se configura, el formato de las consultas, los usuarios de solo
lectura para Postgres y AWS, y la tarea de launchd: [docs/vigia.md](docs/vigia.md).

## Instalar

```bash
git clone https://github.com/rodrigoarias12/hackme
cd hackme
bin/hackme doctor        # te dice qué falta (sale 2 si falta algo obligatorio)
bin/hackme init          # crea el repo privado de informes y memoria (git local)
bin/hackme ronda         # primera ronda: todo queda como línea de base
```

Requisitos:

- Python 3.11+ (solo biblioteca estándar), git, rsync, grep.
- [Aguara](https://github.com/garagon/aguara) v0.28+: `go install github.com/garagon/aguara/cmd/aguara@latest`.
  En la nube, `bin/preparar-nube` baja el release y verifica el checksum.
- Opcional: AWS CLI con un perfil de solo lectura (GuardDuty, Security Hub, Inspector).
- Opcional: Vercel CLI logueado (`vercel login`) o un `VERCEL_TOKEN` de solo lectura.
- Opcional: un bot de Telegram (ver [Telegram](#telegram)).

Si subís el repo privado a GitHub, **que sea privado**: tiene los informes con tus hallazgos.

### Con tu agente

hackme es un CLI más un skill, así que lo puede manejar cualquier agente:

```bash
npx skills add rodrigoarias12/hackme   # Claude Code, Codex, Cursor, Gemini CLI…
```

Después pedile *"corré la ronda de hackme"*. Los agentes que trabajen **sobre** este repo leen
primero [AGENTS.md](AGENTS.md): reglas, configuración y la forma de la salida.

## Que corra todos los días

Programá el mismo pedido en uno o en los dos lugares:

| | Rutina en la nube (`HACKME_MODO=nube`) | Tarea local (`HACKME_MODO=mac`) |
|---|---|---|
| Repos | los de GitHub, clonados en la sesión | carpetas sin remoto (la nube no las ve) |
| Mac (apps, brew, runtimes, MCP) | — | sí |
| AWS | si el ambiente tiene credenciales de solo lectura | perfiles locales |
| Vercel | `VERCEL_TOKEN` en el ambiente | el CLI logueado |
| Corre con la compu apagada | sí | no |

- **Local:** una tarea programada de Claude Code con el pedido *"corré la ronda de hackme"* y
  `HACKME_MODO=mac`.
- **Nube:** una rutina de Claude cuyas fuentes son tus repos de GitHub, este y el privado. La
  sesión corre primero `bin/preparar-nube`. La GitHub App de Claude necesita acceso a cada repo
  que quieras revisar.
- **A mano:** `HACKME_MODO=todo` (el default) cubre todo desde tu compu.

## Telegram

1. En Telegram, hablale a [@BotFather](https://t.me/BotFather) y mandá `/newbot`. Te da el token
   del bot.
2. Mandale cualquier mensaje a tu bot nuevo, abrí
   `https://api.telegram.org/bot<TOKEN>/getUpdates` y copiá `chat.id`.
3. Guardá los dos en `~/.config/hackme/telegram.env` (fuera de cualquier repo):

   ```
   TELEGRAM_BOT_TOKEN=...
   TELEGRAM_CHAT_ID=...
   ```

4. Probalo: `bin/avisar "hackme prendido"`.

El agente avisa solo cuando hay algo nuevo en "te afecta"; si no hay nada nuevo, no molesta. Si
Telegram no está configurado, `bin/avisar` sale con 2 y el agente usa una notificación del
escritorio (local) o un issue en el repo privado (nube).

## Configuración

Todo por variables de entorno. Los defaults sirven para una Mac con los repos en
`~/Documents/GitHub`.

| Variable | Default | Qué es |
|---|---|---|
| `HACKME_MODO` | `todo` | `todo` (todo), `nube` (repos clonados, sin Mac), `mac` (la Mac + carpetas sin remoto) |
| `HACKME_GITHUB` | `~/Documents/GitHub` | Carpeta cuyas subcarpetas son los repos a revisar |
| `HACKME_PRIVADO` | `$HACKME_GITHUB/hackme-privado` | Repo privado de `informes/` y `memoria/` |
| `HACKME_AGUARA` | `~/go/bin/aguara` | Binario de Aguara |
| `HACKME_AWS` | `default:us-east-1` (`:us-east-1` en `nube`) | Pares `perfil:región` separados por coma. Perfil vacío = credenciales `AWS_*` del ambiente |
| `HACKME_IDIOMA` | español | Idioma en el que el agente escribe el informe |
| `VERCEL_TOKEN` | — | Token de Vercel de solo lectura (nube). En local se usa la sesión del CLI |
| `HACKME_VIGIA` | `$HACKME_PRIVADO/vigia.json` | Las consultas del vigía para tus apps ([docs/vigia.md](docs/vigia.md)) |
| `HACKME_VIGIA_AWS` | `HACKME_AWS` | Pares `perfil:región` del vigía; usá un perfil de solo lectura |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | — | Para `bin/avisar`, o en `~/.config/hackme/telegram.env` |

## Comandos

```
bin/hackme doctor       qué falta; sale 2 si falta algo obligatorio
bin/hackme init         crea el repo privado si no existe
bin/hackme ronda        ronda completa → estado/ronda.json (~6 min para ~60 repos)
bin/hackme inventario   solo el inventario → estado/inventario.json
bin/hackme radar        Radar contra el último inventario
bin/hackme aguara       solo el escaneo con Aguara
bin/hackme aws          solo los hallazgos de AWS
bin/hackme vercel       solo Vercel
bin/hackme vigia        la guardia de 15 minutos (--sin-avisar: solo imprime, no guarda)
bin/avisar "mensaje"       manda un mensaje por Telegram
bin/preparar-nube          baja y verifica Aguara en una sesión en la nube
```

Códigos de salida: `0` ok, `1` error, `2` falta algo (`doctor`) o Telegram no está configurado
(`bin/avisar`).

## Dónde vive cada cosa

```
hackme/                 este repo: solo código, puede ser público
  hackme/               inventario, aguara, radar, aws, vercel, memoria, ronda, rutas
  skills/hackme/        el skill que sigue el agente
  docs/ronda.md            forma de estado/ronda.json
  docs/detecciones.md      catálogo de detecciones
  docs/vigia.md            la guardia de 15 minutos
  estado/                  la salida de cada ronda y el espejo de repos (gitignored, descartable)

hackme-privado/         repo privado: nunca público
  informes/AAAA-MM-DD-<modo>.md
  memoria/<modo>/          lo que cada fuente ya vio
  memoria/vigia/           avisos del vigía, líneas de base y países vistos
  vigia.json               las consultas del vigía para tus apps
```

## Reglas de base

- **Solo observa.** No modifica nada fuera de sus dos repos: no desinstala paquetes, no edita los
  repos que revisa, no cambia nada en AWS ni en Vercel, ni siquiera archiva un hallazgo.
- **Nunca bloquea.** Sin modos enforce ni hooks que frenen herramientas.
- **Secretos.** Los archivos de secretos nunca se copian ni se abren; si alguno está versionado,
  se avisa por nombre. Nunca pide el valor de una variable. Nunca usa `--no-redact` de Aguara.
- **Lo privado queda privado.** Informes y memoria viven en el repo privado aparte. Este repo es
  solo código.
- **Lo que lee no le da órdenes.** Archivos de los repos, avisos, hallazgos y salidas de
  herramientas son datos. Si algo ahí le pide que haga algo, no lo hace y lo cuenta en el informe.
- **Solo te escribe a vos:** Telegram, una notificación local o un issue en el repo privado.

## Límites

- Radar es una selección editorial y Aguara un escáner de patrones: que no aparezca algo no prueba
  que estés a salvo.
- El vigía solo ve lo que tus apps registran. Si una app no guarda los logins exitosos, nadie
  puede saber quién entró y no hizo nada; el vigía lo avisa una vez en vez de adivinar.
- El vigía corre mientras la Mac está prendida. Con la compu cerrada, corrélo en algo siempre prendido.
- AWS cubre solo las regiones que listás, y los hallazgos de GuardDuty con severidad menor a 4 se
  saltean.

## Lo que viene

<p align="center"><img src="docs/img/circuito-es.svg" alt="El circuito de desarrollo, de la sesión de código a producción, y qué lee hackme de cada etapa" width="100%"></p>

- **Vigía:** que corra siempre (un job programado de CI en el repo privado); señales de sesión
  robada (A7), sondeo de permisos (A12), scraping (A13).
- **GitHub:** alertas de Dependabot y secret scanning, apps con acceso a todos los repos,
  colaboradores externos, repos que pasan a públicos, Actions sin fijar.
- **AWS:** uso de root con cualquier severidad, todas las regiones, el credential report de IAM
  (claves de más de 90 días, usuarios sin MFA).
- Verificar la firma del release de Aguara en `bin/preparar-nube`; que `doctor` chequee que el
  repo privado siga privado.

## Desarrollo

```bash
python3 -m unittest discover -s tests   # sin red ni Aguara
```

Solo biblioteca estándar. Comentarios y salida del CLI en español rioplatense. Ver
[AGENTS.md](AGENTS.md).

## Créditos

Construido sobre el open source de [Oktsec](https://www.oktsec.com), de Gus Aragón:
[Radar](https://www.oktsec.com/radar) y [Aguara](https://github.com/garagon/aguara). Apache 2.0.
