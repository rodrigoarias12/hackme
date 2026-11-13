# hackme

[Español](README.es.md)
<p align="center"><img src="docs/img/banner-en.svg" alt="hackme: a security agent that finds vulnerabilities, proves them and proposes the fix" width="100%"></p>

A security agent that **hunts for vulnerabilities in everything you run**: your repos, your Mac,
your AWS account and your Vercel teams. It turns every serious lead into an investigation with
evidence, and when a vulnerability is confirmed it proposes the fix and, with your OK, opens the
pull request. Every day it cross-matches [Oktsec Radar](https://www.oktsec.com/radar)
advisories against your real inventory, scans every repo with
[Aguara](https://github.com/garagon/aguara), reads what AWS GuardDuty, Security Hub and Inspector
found, audits your Vercel teams and projects, and tells you only what is new and affects you,
on Telegram.

Every 15 minutes, the **vigía** watches what is happening right now: someone sweeping your
routes, spraying logins, using the AWS root account, turning logs off. It alerts on Telegram
while it happens.

It blocks nothing and changes nothing on its own. The one thing it does besides reading is a
pull request with the fix, and only after you approve that specific PR. It never merges, deploys
or tests an attack against a live system.

**Use it as it is, or as the base for your own security agent.** Every piece (the rules, the
skill, each source, the 15-minute detections, the detection catalog) is separate and documented,
so you can keep the ones you need and add your own. See
[Build your own security agent](#build-your-own-security-agent).

- [How it works](#how-it-works)
- [What it watches](#what-it-watches)
- [Vigía: the 15-minute watch](#vigía-the-15-minute-watch)
- [Attack paths](#attack-paths)
- [From lead to fix](#from-lead-to-fix)
- [It audits itself](#it-audits-itself)
- [Install](#install)
- [Run it every day](#run-it-every-day)
- [Telegram](#telegram)
- [Configuration](#configuration)
- [Commands](#commands)
- [Build your own security agent](#build-your-own-security-agent)
- [Where things live](#where-things-live)
- [Ground rules](#ground-rules)
- [Limits](#limits)
- [Roadmap](#roadmap)

## How it works

<p align="center"><img src="docs/img/flujo-en.svg" alt="How hackme works: a daily round and a 15-minute watch, both reading behind a read-only boundary, alerting on Telegram" width="100%"></p>

```
bin/hackme ronda
  ├─ inventario   every folder in ~/Documents/GitHub + the Mac
  │               (npm/PyPI/Go packages, Docker images, Actions, MCP configs, services,
  │                apps, brew, Cursor/VS Code extensions, runtimes)
  ├─ aguara       secret-free mirror → scan with --monitor
  │               + compromised-package check on the real repo
  │               + secret files committed to git (names only)
  ├─ radar        Radar's items.json × inventory → candidates with a match strength
  │               (version-afectada / nombre / mencion)
  ├─ aws          GuardDuty, Security Hub and Inspector findings (read only)
  └─ vercel       teams, env var hygiene, previews, firewall, audit log (read only)
        ↓
  estado/ronda.json  (shape: docs/ronda.md)
        ↓
  the agent (skills/hackme/SKILL.md) judges each candidate, writes the report in a
  private repo and notifies you on Telegram if something is new
```

Two layers on purpose:

- **The CLI** (`hackme/`, Python stdlib only) is deterministic: it collects, matches and
  remembers what it already saw. Matching is generous; it never decides "you are affected".
- **The skill** is where an agent applies judgment: it compares the locked version with the
  advisory's range, reads the cited line before calling something real, drops test fixtures, and
  writes a short report in plain language.

Every source keeps memory between rounds (`nuevo` / `actualizado` / `visto` / `línea de base`), so
the first run is a baseline and later runs only surface what changed.

## What it watches

| Source | What it looks for | How |
|---|---|---|
| **Inventory** | Every package, image, GitHub Action, MCP server, service and env var *name* in your repos; apps, brew, editor extensions, runtimes, global npm and MCP configs on the Mac | Reads manifests and lockfiles. `.env.example` only, never real `.env` |
| **Oktsec Radar** | Advisories (vulnerabilities, supply-chain attacks, platform breaches, threat activity) that match something you actually run | `items.json` × inventory; exact affected versions from OSV data when Radar has it |
| **Aguara** | Prompt injection and dangerous instructions in skills, `CLAUDE.md`/`AGENTS.md`, MCP configs and workflows; hardcoded credentials; compromised packages; secret files committed to git | `aguara scan --monitor` on a mirror without secrets, `aguara check` on the real repo, `git ls-files` for secret file names |
| **AWS** | GuardDuty findings (severity 4+), Security Hub HIGH/CRITICAL, Inspector HIGH/CRITICAL | AWS CLI with a read-only profile, one or more `profile:region` pairs |
| **Vercel** | Pending access requests and new team members; secret-looking variables with a public prefix (they ship to the browser); `plain` secrets; production secrets also in `development` (anyone running `vercel env pull` takes them home); production secrets not marked `sensitive`; unprotected previews and disabled firewall on projects with a custom domain; stale published projects; audit events (`env pull`, variables changed, members, tokens, protection, firewall); Vercel's own security check (members without MFA, tokens that never expire, too many owners); open Vercel Security Review vulnerabilities in your own code, by severity and environment | Vercel REST API through the logged-in CLI (`vercel api`) or `VERCEL_TOKEN`; Security Review through `vercel security vulnerabilities list` (CLI ≥ 65), never `dismiss` or `reopen`. Only each variable's `key`, `type` and `target`, never its value |

<p align="center"><img src="docs/img/detecciones-en.svg" alt="82 detections by family: 38 running, 8 partial, 36 to do" width="100%"></p>

The full list of detections, built and planned, grounded in OWASP, MITRE ATT&CK and the CIS
benchmarks, is in [docs/detecciones.md](docs/detecciones.md).

## Vigía: the 15-minute watch

<p align="center"><img src="docs/img/ataque-en.svg" alt="A route scan to scale: one IP crosses the threshold at 02:23 and the vigía alerts at 02:30" width="100%"></p>

```
bin/hackme vigia               every 15 min (launchd on the Mac)
  ├─ your apps    SQL you write, read-only: request log, login events, accounts
  │               → route sweeps, scanners, firewall surges, spraying, logins after
  │                 failures, new countries, a log that went silent, dormant accounts
  └─ aws          CloudTrail write events + GuardDuty at any severity for what matters
                  → root use, console login without MFA, logs off, IAM, S3, KMS, network
        ↓
  Telegram, once per key per day, max 25 a day
```

Deterministic, no AI. Setup, the query format, the read-only users for Postgres and AWS, and the
launchd job: [docs/vigia.md](docs/vigia.md).

## Attack paths

A list of findings doesn't tell you how someone gets in. Every round, hackme starts from what an
attacker wants (the production database, the AWS account, Vercel's production secrets, the code)
and builds concrete chains from what it found, each step backed by evidence:

> **Production database ← from the internet, directly**
> the database is reachable from the internet (Security Hub RDS.46) → IPs with a bad reputation
> already probe it (GuardDuty) → a login from one of them succeeded (GuardDuty) · *cut: take it off
> the public subnet and rotate that user's password*

Each path says which fix cuts it. The round tells you when a path **opens** and when one
**closes**, and a path someone already walked (a successful login from a malicious IP) goes first.
On Mondays, or when you ask, the agent writes a full audit: what's worth stealing, every path with
the evidence it checked, paths it found beyond the rules, and the fixes in order. It never tests a
path against a live system. `bin/hackme caminos` rebuilds them from the last round.

## From lead to fix

What a scanner or a model says is a lead, not a finding. Every round, each serious lead from any
source becomes an **investigation** in the private repo, without waiting for you to ask:

| Source | What opens an investigation |
|---|---|
| Vercel Security Review | `critical` and `high` vulnerabilities in your code |
| Aguara | Critical and high rules in what agents read, hardcoded keys, committed secret files, compromised packages (one per rule and repo) |
| Oktsec Radar | An advisory that matches a version in your inventory, or a name when it is already being exploited |
| GuardDuty | Severity 7 and up, grouped by type and resource |
| Security Hub | Failed `CRITICAL` and `HIGH` controls |
| Inspector | `CRITICAL` and `HIGH` CVEs, grouped by package and resource |
| Vercel | Secrets that reach the browser, members without MFA, pending access requests |
| The agent | What it finds itself: every round it reviews one repo in depth, the way an attacker would |

hackme gathers what it can without running anything (the cited code and whether it is still the
same, the flagged files, the locked version, the configuration as the API shows it). Then the
agent verifies and gives a verdict. `bin/hackme investigar objetivos` says which repo is next for
the in-depth review, from what the round saw in each and how long since it was last reviewed. Every piece of evidence carries its type, so nobody states more than was
proven:

| Type | Means |
|---|---|
| `observado` | It was seen directly: this file, at this commit, says this |
| `deducido` | It is concluded from something else: a scanner says so, a setting implies it |
| `sin-probar` | What would have to be run to know, and wasn't |

An investigation ends `confirmada` (it needs something the agent observed itself), `descartada` or
`bloqueada` (with what is missing). A closed one reopens on its own if the code it cited changes,
and becomes `arreglada` when a source that ran fine stops reporting it. Only investigations that
live in a GitHub repo can end in a pull request; for the rest (AWS, Vercel settings) the steps go
in the report for you.

From a confirmed investigation the agent proposes **one action: a pull request with the fix**. You
get it on Telegram and approve it, one at a time:

```
bin/hackme investigar                      leads → investigations with evidence (the round runs it)
bin/hackme investigar lista                every open investigation, most severe first
bin/hackme investigar ver <id>             the claim, the evidence and the next step
bin/hackme investigar objetivos            which repo to review in depth next, and why
bin/hackme acciones                        what is proposed, approved and done
bin/hackme acciones aprobar <id>           your OK for that one PR (in a terminal: type "si")
```

Once approved, the agent clones the repo into a disposable folder, writes the fix and a test on a
`hackme/<id>` branch, opens the PR and records its URL. It never merges, deploys, force-pushes,
pushes to the default branch or touches your own checkout, and a scheduled round only proposes:
it never approves or executes. The self-audit below checks all of that.

## It audits itself

A security agent should be checked like anything else. Every round runs `bin/hackme huella`: it
reads the Claude Code session logs of the last 26 hours (every command the agent ran, every file it
read or wrote, everything it sent) and checks them against the hard rules:

| Rule | What breaks it |
|---|---|
| Writes only in its two repos | a write, a `git commit` or a `rm` anywhere else |
| Never touches secrets | opening a `.env`, `~/.aws/credentials`, keys; `--no-redact`; `vercel env pull` |
| Changes nothing | an `aws` call that isn't describe/list/get, a `vercel` or `gh` command that writes |
| Talks only to known hosts | a request to a host outside Telegram and the APIs it reads |
| Never blocks | uninstalls, `aguara clean`, enforce modes |

The result goes to the private repo (`huellas/`) and any serious finding goes at the top of the
report and to Telegram. It's heuristic (it reads commands as text), so it marks for review. Tools
that go through MCP can also be recorded with [oktsec](https://www.oktsec.com) in observe mode.

## Install

### Let your agent install it

Paste this into Claude Code (or Codex, Cursor, Gemini CLI):

> Install hackme from https://github.com/rodrigoarias12/hackme. Clone it next to my projects,
> read `skills/hackme-setup/SKILL.md` and follow it. Ask me before installing anything.

The agent checks what you already have, installs what is missing with your OK, connects each
source in read-only mode, runs the first round, explains the report and schedules the round to
run every day. It never asks for a key or a password: logins are commands you run yourself. The
whole script it follows is [skills/hackme-setup/SKILL.md](skills/hackme-setup/SKILL.md).

In Claude Code you can also add it as a plugin, which brings both skills (`hackme` and
`hackme-setup`):

```
/plugin marketplace add rodrigoarias12/hackme
/plugin install hackme@hackme
```

Then ask it to *"set up hackme"*.

### By hand

```bash
git clone https://github.com/rodrigoarias12/hackme
cd hackme
bin/hackme doctor        # what is there, what is missing and how to fix it (exit 2 if something required is missing)
bin/hackme config poner HACKME_GITHUB ~/code    # only if your repos are not in ~/Documents/GitHub
bin/hackme init          # creates the private repo for reports and memory (local git)
bin/hackme ronda         # first round: everything becomes the baseline
```

Requirements:

- Python 3.11+ (stdlib only), git, rsync, grep.
- [Aguara](https://github.com/garagon/aguara) v0.28+. `bin/instalar-aguara` downloads the official
  release for macOS or Linux and refuses to install if the checksum does not match:
  `bin/hackme config poner HACKME_AGUARA "$(bin/instalar-aguara)"`. Or, with Go:
  `go install github.com/garagon/aguara/cmd/aguara@latest`.
- Optional: AWS CLI with a read-only profile (GuardDuty, Security Hub, Inspector).
- Optional: Vercel CLI logged in (`vercel login`), or a read-only `VERCEL_TOKEN`.
- Optional: a Telegram bot (see [Telegram](#telegram)).

If you push the private repo to GitHub, **make it private**: it holds reports with your findings.

### With your coding agent

hackme is a CLI plus two skills (`hackme` runs the round, `hackme-setup` installs it), so any
coding agent can drive it:

```bash
npx skills add rodrigoarias12/hackme   # Claude Code, Codex, Cursor, Gemini CLI, …
```

Then ask it to *"set up hackme"* the first time and *"run the hackme round"* after that. Agents working **on** this repo read
[AGENTS.md](AGENTS.md) first: hard rules, configuration and the output contract.

## Run it every day

Schedule the same prompt in one or both places:

| | Cloud routine (`HACKME_MODO=nube`) | Local task (`HACKME_MODO=mac`) |
|---|---|---|
| Repos | the ones on GitHub, cloned into the session | folders without a git remote (the cloud can't see them) |
| Mac (apps, brew, runtimes, MCP) | — | yes |
| AWS | if the environment has read-only credentials | local profiles |
| Vercel | `VERCEL_TOKEN` in the environment | the logged-in CLI |
| Runs with your laptop off | yes | no |

- **Local:** a Claude Code scheduled task with the prompt *"run the hackme round"* and
  `HACKME_MODO=mac`.
- **Cloud:** a Claude routine whose sources are your GitHub repos plus this one and the private
  repo. The session runs `bin/preparar-nube` first. The Claude GitHub App needs access to every
  repo you want scanned.
- **Manual:** `HACKME_MODO=todo` (the default) covers everything from your machine.

## Telegram

1. In Telegram, talk to [@BotFather](https://t.me/BotFather) and send `/newbot`. It gives you the
   bot token.
2. Send any message to your new bot, then open
   `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy `chat.id`.
3. Save both in `~/.config/hackme/telegram.env` (outside any repo):

   ```
   TELEGRAM_BOT_TOKEN=...
   TELEGRAM_CHAT_ID=...
   ```

4. Test it: `bin/avisar "hackme is on"`.

The agent only notifies when something in "affects you" is new; with nothing new it stays quiet.
If Telegram isn't configured, `bin/avisar` exits with 2 and the agent falls back to a desktop
notification (local) or an issue in the private repo (cloud).

## Configuration

Save a setting with `bin/hackme config poner <VARIABLE> <value>`: it goes to
`~/.config/hackme/config.env`, so scheduled runs find it without anyone exporting anything.
`bin/hackme config` shows what is in effect. An environment variable always wins over the file,
and the file never holds secrets. The defaults work for a Mac with repos in `~/Documents/GitHub`.

| Variable | Default | What it is |
|---|---|---|
| `HACKME_MODO` | `todo` | `todo` (everything), `nube` (cloud: cloned repos, no Mac), `mac` (the Mac + folders without a remote) |
| `HACKME_GITHUB` | `~/Documents/GitHub` | Folder whose subfolders are the repos to scan |
| `HACKME_PRIVADO` | `$HACKME_GITHUB/hackme-privado` | Private repo for `informes/` and `memoria/` |
| `HACKME_AGUARA` | `~/go/bin/aguara` | Aguara binary |
| `HACKME_AWS` | `default:us-east-1` (`:us-east-1` in `nube`) | Comma-separated `profile:region` pairs. Empty profile = `AWS_*` credentials from the environment |
| `HACKME_IDIOMA` | Spanish | Language the agent writes the report in |
| `HACKME_PYTHON` | the first Python 3.11+ found | Interpreter `bin/hackme` uses (environment only) |
| `VERCEL_TOKEN` | — | Read-only Vercel token (cloud). Locally the CLI session is used |
| `HACKME_VIGIA` | `$HACKME_PRIVADO/vigia.json` | The vigía's app queries ([docs/vigia.md](docs/vigia.md)) |
| `HACKME_VIGIA_AWS` | `HACKME_AWS` | `profile:region` pairs for the vigía; use a read-only profile |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | — | For `bin/avisar`, or in `~/.config/hackme/telegram.env` |

## Commands

```
bin/hackme doctor       what is there, what is missing and how to fix it: requirements, each source,
                        the daily routine (--json for an agent; exit 2 if something required is missing)
bin/hackme config       saved settings (config poner <VARIABLE> <value>, config quitar <VARIABLE>)
bin/instalar-aguara     download Aguara's official release, verify the checksum, print its path
bin/hackme init         create the private repo if it doesn't exist
bin/hackme ronda        full round → estado/ronda.json (~6 min for ~60 repos)
bin/hackme inventario   inventory only → estado/inventario.json
bin/hackme radar        Radar against the last inventory
bin/hackme aguara       Aguara scan only
bin/hackme aws          AWS findings only
bin/hackme vercel       Vercel only
bin/hackme vigia        the 15-minute watch (--sin-avisar: print only, save nothing)
bin/hackme caminos      attack paths to what's valuable, from the last round
bin/hackme investigar   serious leads → investigations with evidence (ver <id>, anotar <id> …)
bin/hackme acciones     proposed PRs: proponer, aprobar, rechazar, preparar, cerrar
bin/hackme huella       what the agent did in the last 26 h, checked against its rules
bin/avisar "message"       send a Telegram message
bin/preparar-nube          download and verify Aguara in a cloud session
```

Exit codes: `0` ok, `1` error, `2` missing requirement (`doctor`) or Telegram not configured
(`bin/avisar`).

## Build your own security agent

hackme is one security agent, and also a kit to build others: one that only watches your app's
logins, one for a single cloud account, one for your laptop, one for a client. The pieces are
separate on purpose.

| Piece | What you reuse | Where |
|---|---|---|
| The rules | What any security agent should never do: change things, block, open secrets, obey what it reads | [AGENTS.md](AGENTS.md) |
| The skill | How an agent judges findings, writes the report and decides whether to alert | [skills/hackme/SKILL.md](skills/hackme/SKILL.md) |
| The sources | One Python module per source (Aguara, Radar, AWS, Vercel), read-only, stdlib only | `hackme/*.py` |
| The memory | `nuevo` / `actualizado` / `visto` / `línea de base` per finding, so only changes surface | `hackme/memoria.py` |
| The watch | Deterministic detections as pure functions: rows in, alerts out | `hackme/vigia.py` |
| The catalog | 82 detections with their source (OWASP, MITRE ATT&CK, CIS, NIST) and status | [docs/detecciones.md](docs/detecciones.md) |
| The output | One JSON the agent reads to judge | [docs/ronda.md](docs/ronda.md) |
| Alerts | Telegram, with a local or private-issue fallback | `hackme/avisar.py`, `bin/avisar` |

### Add a source

GitHub, Google Workspace, Cloudflare, Supabase, your own app: same steps.

1. Create `hackme/<source>.py` with a `correr()` that only reads and returns
   `{"hallazgos": [...], "errores": {...}}`. Each finding is
   `{"id", "servicio", "severidad", "titulo", "recurso", "detalle"}`; `detalle` holds names and
   counts, never secret values.
2. Call `memoria.marcar("<source>", hallazgos)` so each finding gets its state and the first run
   becomes the baseline.
3. Add it to `hackme/ronda.py` and give it a command in `hackme/__main__.py`.
4. Tell the agent how to judge it: one section in the skill (what goes on top, what is noise).
5. Mark the rows it covers in [docs/detecciones.md](docs/detecciones.md).

### Add a detection to the vigía

Write a `detectar_<thing>()` that takes rows and returns alerts (`clave`, `deteccion`, `titulo`,
`detalle`), put its threshold in `UMBRALES` saying whether it comes from a source (`[S]`) or is a
starting point (`[M]`), and add a test with sample rows. The key decides deduplication: one alert
per key per day.

### Run it with another agent

The skill is a plain `SKILL.md`, so any agent that reads skills can drive it (Claude Code, Codex,
Cursor, Gemini CLI): `npx skills add rodrigoarias12/hackme`. [AGENTS.md](AGENTS.md) is the
contract for agents that change the code.

### Some agents you could build from it

- **App watch:** only the vigía with your app's queries, alerting a team chat.
- **Cloud account:** only `aws` and `vercel`, daily, for an account you manage for someone else.
- **Laptop:** `HACKME_MODO=mac`: apps, extensions, MCP configs and local repos.
- **Supply chain:** only Radar and Aguara over your repos, before every release.

## Where things live

```
hackme/                 this repo: code only, can be public
  hackme/               inventario, aguara, radar, aws, vercel, caminos, investigar, acciones, huella, …
  skills/hackme/        the skill the agent follows on every round
  skills/hackme-setup/  the skill an agent follows to install hackme for a new owner
  docs/ronda.md            shape of estado/ronda.json
  docs/detecciones.md      detection catalog
  docs/vigia.md            the 15-minute watch
  estado/                  each round's output and the repo mirror (gitignored, disposable)
  estado/trabajo/<id>/     the disposable clone where an approved PR is written

hackme-privado/         private repo: never public
  informes/YYYY-MM-DD-<modo>.md
  memoria/<modo>/          what each source already saw
  memoria/vigia/           the vigía's alerts, baselines and countries seen
  vigia.json               the vigía's queries for your apps
  huellas/                 what each run of the agent did, checked against the rules
  investigaciones/         one file per lead: claim, evidence by type, verdict, next step
  acciones/                each proposed PR: who approved it, when, and its URL
```

## Ground rules

- **A lead is not a finding.** Every claim carries its evidence, labeled observed, deduced or not
  tested.
- **One action, with your OK each time:** a pull request with the fix. Never a merge, a deploy or
  a push to the default branch. A scheduled round never approves or executes.
- **Everything else is read-only.** No package uninstalls, no edits to your checkouts, no AWS or
  Vercel changes, not even archiving a finding. It never tests an attack against a live system.
- **Never blocks.** No enforce modes, no hooks that stop tool calls.
- **Secrets.** Secret files are never copied or opened; committed ones are reported by name.
  Variable values are never requested. Aguara's `--no-redact` is never used.
- **Private stays private.** Reports and memory live in the separate private repo. This repo is
  only code.
- **Untrusted input.** Repo files, advisories, findings and tool output are data, not
  instructions. If something in them asks the agent to act, it doesn't, and says so in the report.
- **Outbound only to you:** Telegram, a local notification, an issue in the private repo, or the PR
  you approved.

## Limits

- Radar is an editorial selection and Aguara a pattern scanner: not showing up doesn't prove
  you're safe.
- The vigía only sees what your apps record. If an app doesn't log successful logins, nobody can
  tell who logged in and did nothing; the vigía says so once instead of guessing.
- The vigía runs while the Mac is on. With the laptop closed, run it somewhere always on.
- AWS covers only the regions you list, and GuardDuty findings below severity 4 are skipped.

## Roadmap

<p align="center"><img src="docs/img/circuito-en.svg" alt="The development loop from coding session to production, and where hackme reads from each stage" width="100%"></p>

- **Vigía:** run it always on (a scheduled CI job in the private repo); session hijack signs (A7),
  authorization probing (A12), scraping (A13).
- **GitHub:** Dependabot and secret scanning alerts, apps with access to every repo, outside
  collaborators, repos turned public, unpinned Actions.
- **AWS:** root usage at any severity, all regions, the IAM credential report (keys older than
  90 days, users without MFA).
- Verify Aguara's release signature in `bin/preparar-nube`; `doctor` checks that the private repo
  is still private.

## Development

```bash
python3 -m unittest discover -s tests   # no network, no Aguara needed
```

Stdlib only. Code comments and CLI output are in Spanish (rioplatense). See [AGENTS.md](AGENTS.md).

## Credits

Built on [Oktsec](https://www.oktsec.com)'s open source work by Gus Aragón:
[Radar](https://www.oktsec.com/radar) and [Aguara](https://github.com/garagon/aguara).
Apache 2.0.
