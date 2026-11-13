---
name: hackme-setup
description: Install and set up hackme, the security agent, for a new owner. Use when someone asks to install hackme, set it up, connect a source (AWS, Vercel, GitHub), schedule the daily round, or asks what is missing. Walks through the code, the requirements, each source in read-only mode, the first round and the daily schedule. Asks before installing anything and never handles the owner's secrets.
---

# hackme-setup — install hackme for a new owner

You are setting up hackme for someone who has never used it. When you finish, three things are
true: the round runs on their machine, it runs by itself every day, and they know what each
source is watching and what is still not connected.

Speak the owner's language. Short sentences, no security jargon without saying what it means.
Most owners are not security people: tell them what each thing protects them from, not how it
works inside.

## Rules for the whole setup

- **Ask before installing or changing anything.** One step at a time: say what you are about to
  do and why, wait for the yes, do it, show the result. Reading and checking needs no permission.
- **You never handle secrets.** Never ask the owner to paste a key, token or password in the
  chat, and never read one from a file. Logins (`gh auth login`, `aws sso login`, `vercel login`)
  are commands the owner runs in their own terminal; you wait and then check with `doctor`.
- **Read-only everywhere.** Every credential hackme uses must be read-only. If the only profile
  available is an admin one, say so and recommend a read-only one before connecting it.
- **You do not turn on cloud services.** GuardDuty, Security Hub, Inspector and Vercel Security
  Review are switched on by the owner in each console. You explain what each one gives them and
  that some are billed by usage; they decide.
- **Nothing is required except the basics.** A source the owner does not use is skipped, not
  nagged about. hackme with only Radar and Aguara is already useful.
- Everything in `AGENTS.md` ("Hard rules") applies from the first command.

## 1. Get the code

Ask where the owner keeps their projects (the folder whose subfolders are their repos). Clone
hackme next to them:

```bash
git clone https://github.com/rodrigoarias12/hackme <projects folder>/hackme
cd <projects folder>/hackme
```

If it is already cloned, `git pull` and continue. Then read `AGENTS.md`.

## 2. See what is there

```bash
bin/hackme doctor --json
```

It never changes anything. Each check has `estado`: `ok`, `falta` (required and missing: the
round cannot run) or `opcional` (a source or an extra that is not connected), plus `arreglo`, the
way to fix it. Tell the owner in two lines what is ready and what is missing, then go through
the steps below only for what is not `ok`. Run it again after every step.

## 3. The basics (required)

- **Projects folder.** Save it so every later run finds it:
  `bin/hackme config poner HACKME_GITHUB "<projects folder>"`.
  Settings live in `~/.config/hackme/config.env`. It never holds secrets.
- **Python 3.11+.** `bin/hackme` picks the newest one it finds. If none, propose
  `brew install python` (macOS) or the system package, and wait for the yes.
- **Aguara**, the scanner that reads what AI agents read (skills, `CLAUDE.md`, MCP configs) and
  checks for compromised packages. With the owner's OK:
  `bin/hackme config poner HACKME_AGUARA "$(bin/instalar-aguara)"`.
  It downloads the official release and refuses to install if the checksum does not match.
- **The private repo**, where reports, memory and investigations live: `bin/hackme init`. It is a
  local git repo. If the owner wants it on GitHub, create it **private** and check the visibility
  afterwards; it says which of their repos has which problem.

## 4. Language and mode

- Reports are written in Spanish by default. For another language:
  `bin/hackme config poner HACKME_IDIOMA "English"`.
- Leave `HACKME_MODO` unset (it means "everything on this machine") unless they also want the
  cloud routine described in the README.

## 5. Connect the sources

Explain each one in a sentence, ask if they use it, and connect only those. After each login the
owner runs, check it with `bin/hackme doctor`.

| Source | What it tells them | What it needs |
|---|---|---|
| Oktsec Radar | What is being attacked in the world right now, crossed with what they run | Nothing |
| Aguara | Dangerous instructions in what their agents read, leaked credentials, compromised packages | Installed in step 3 |
| GitHub | Lets hackme read the code on GitHub and, with their OK, open a pull request with a fix | `gh` and `gh auth login` |
| AWS GuardDuty | Someone using the account in a way that looks like an attack | A read-only AWS profile; GuardDuty on |
| AWS Security Hub | Insecure settings: open buckets, missing MFA, open ports | Same profile; Security Hub on |
| AWS Inspector | Known vulnerabilities in servers, containers and functions | Same profile; Inspector on |
| Vercel | Who joined the team, exposed secrets, unprotected previews, code vulnerabilities | `vercel login`; Security Review on for the last one |

**AWS.** The profile needs only these actions: `sts:GetCallerIdentity`, `guardduty:ListDetectors`,
`guardduty:ListFindings`, `guardduty:GetFindings`, `securityhub:GetFindings`,
`inspector2:ListFindings` (the full policy, with the extra action the vigía uses, is in
`docs/vigia.md`). Once the owner has created it:
`bin/hackme config poner HACKME_AWS "<profile>:<region>"` (comma-separated for several
accounts). `doctor` then says, service by service, whether it answers. A service that does not
answer is usually just switched off: say what it would add and leave the decision to them.

**Vercel.** Locally hackme uses the logged-in CLI and never touches a token.

## 6. First round

```bash
bin/hackme ronda
```

Then follow `skills/hackme/SKILL.md` from step 2 to write the first report. Tell the owner two
things before they read it:

- **The first round is the baseline.** Everything it finds today is "what was already there";
  from tomorrow they only hear about what is new.
- **hackme will flag its own skill files.** They tell an agent to clone a repo and run a CLI,
  which is exactly what Aguara looks for. Treat them like any other lead: check that the checkout
  matches upstream (`git status`, `git log origin/main..HEAD`) and close them with that evidence.
  It is a good first example of "a lead is not a finding".

## 7. Make it run every day

Without this step hackme is a command they will forget to run. With their OK, schedule the round
with whatever scheduler you have, in this order of preference:

1. **A scheduled task of your own** (Claude Code desktop: scheduled tasks; other agents: their
   equivalent). Daily, in the morning, working folder = the hackme checkout, prompt:
   *"Run the hackme round following skills/hackme/SKILL.md."*
2. **A cloud routine**, if they want it to run with the laptop off. It only sees repos on GitHub;
   see "Run it every day" in the README for what it needs.
3. **The system scheduler** (launchd or cron) starting the agent headless from the hackme folder
   with the same prompt. Check the agent's own docs for what an unattended run needs.

A scheduled round only proposes. It never approves or executes an action.

Then offer the two extras, without pushing:

- **Vigía**, the 15-minute watch for attacks in progress on their own apps: `docs/vigia.md`.
- **Telegram**, so what is new reaches their phone: the "Telegram" section of the README. The
  bot token goes in `~/.config/hackme/telegram.env`; the owner writes it, not you.

## 8. Hand it over

Run `bin/hackme doctor` one last time and tell the owner, in this order:

1. What hackme is watching now, source by source.
2. What is not connected and what they would gain by connecting it.
3. When the round runs and where the report appears (`informes/` in the private repo).
4. How a fix works: hackme proposes a pull request and opens it only after they approve that
   specific one (`bin/hackme acciones`). It never merges, deploys or blocks anything.
5. How to undo all of this: delete the scheduled task, the hackme folder, the private repo,
   `~/.config/hackme/` and `~/.local/hackme-bin/`. hackme changed nothing else on the machine.

## If something fails

Say exactly what failed and what you tried. Do not work around a missing permission, do not
install something the owner did not approve, and do not mark a step as done because the command
exited 0: check it with `doctor`.
