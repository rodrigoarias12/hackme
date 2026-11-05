# Detection catalog

What a security team watches, taken from published sources (OWASP AppSensor and the Logging
Vocabulary, MITRE ATT&CK, the CIS AWS Foundations Benchmark, CIS Controls v8, NIST SP 800-55 and
800-63B, AWS GuardDuty, GitHub and Vercel docs), mapped to what hackme does or will do.

**Status:** ✅ built · ◐ partly built · ○ planned.
**Cadence:** `15m` = the vigía (fast watch, planned) · `D` = the daily round · `W` = weekly.
**Thresholds:** **[S]** comes from the source; **[M]** is a starting point to tune on your own data.

Source keys are listed at the end. Every row alerts **only**: hackme never blocks.

## Before using this list

- **OAuth login (Google, GitHub…).** The app never sees passwords, so password guessing happens at
  the identity provider. In the app, failed or denied logins mean OAuth errors or accounts that
  aren't allowed in. The brute-force rows still work as patterns; they just fire less.
- **GitHub audit log** keeps 180 days and its API needs GitHub Enterprise Cloud (`git.clone` too).
  On Free or Team, use organization webhooks plus polling the REST API for current state.
- **Vercel audit log** has the full event list on Enterprise. Log drains work on any plan and carry
  `proxy.clientIp`, `proxy.path`, `proxy.statusCode`, `proxy.wafAction`
  (log/challenge/deny/bypass/rate_limit), `proxy.wafRuleId` and `proxy.responseByteSize`. Without
  Enterprise, config changes are found by comparing API snapshots between rounds.
- **CIS AWS monitoring controls (4.1–4.16)** are "manual" in Security Hub for CIS v3 and v5, so
  Security Hub does not alert on them. They have to be read from CloudTrail. The CIS alarm
  threshold is ≥ 1.

## 0. Daily round (what is built today)

| # | Detection | Signal | Status | Source |
|---|---|---|---|---|
| R1 | Advisory affects something you run | Radar `items.json` × inventory, OSV affected versions | ✅ D | Oktsec Radar; ATT T1195 |
| R2 | Prompt injection / dangerous instructions in the agentic surface (skills, `CLAUDE.md`, MCP configs, workflows) | `aguara scan --monitor` | ✅ D | Aguara; ATT T1195.001 |
| R3 | Compromised package installed | `aguara check` | ✅ D | Aguara; ATT T1195.001 |
| R4 | Secret files committed to git | `git ls-files` against secret patterns (names only) | ✅ D | ATT T1552.001; CIS Controls 3.11 |
| R5 | Hardcoded credentials | Aguara `CRED_*` rules, redacted | ✅ D | ATT T1552.001 |
| R6 | Secret with a public prefix (ships to the browser) | Vercel env var names | ✅ D | ATT T1552 |
| R7 | Production secrets also in `development` / not `sensitive` / `plain` | Vercel env var `type` and `target` | ✅ D | ATT T1552; CIS Controls 3.3 |
| R8 | Unprotected previews, firewall off on custom domains | Vercel project settings | ✅ D | ATT T1190 |
| R9 | Stale published projects | Vercel last deploy > 180 days [M] | ✅ D | CIS Controls 1.1, 2.2 (inventory) |
| R10 | GuardDuty severity 4+, Security Hub and Inspector HIGH/CRITICAL | AWS APIs | ✅ D | GD-IAM; GD-RDS; CIS v5 |

## A. Attack in progress (15m)

| # | Detection | What it detects | Signal | Threshold | Status | Source |
|---|---|---|---|---|---|---|
| A1 | Failures on one account | Repeated bad credentials against one account | Failed logins by user | [M] ≥ 5 in 15m. [S] NIST caps lockout at ≤ 100 consecutive failures | ✅ 15m | AS AE2; LV `authn_login_fail`, `authn_login_fail_max`; ATT T1110.001; NIST63B §3.2.2 |
| A2 | Spray from one IP | One IP trying many usernames, or a high login rate | Failed logins by IP, distinct users | [M] ≥ 10 distinct users or ≥ 20 attempts per IP in 15m | ✅ 15m | AS AE1, AE3, AE12; ATT T1110.003; OAT-007 |
| A3 | Distributed stuffing | Site-wide rise in failures across many IPs | Failed logins vs. 7-day baseline | [M] > 3× the same slot | ✅ 15m | AS STE2; ATT T1110.004; OAT-008 |
| A4 | Success after failures | A failure run that ends in a login | Success after ≥ N failures, same user or IP, 1h | [M] N = 5, high priority | ✅ 15m | LV `authn_login_successafterfail`; ATT T1110, T1078 |
| A5 | Denied logins | Accounts outside the allowlist trying to get in | Denied logins | [M] ≥ 3 per IP in 15m, or any denial of an email from your own domain (offboarded user) | ✅ 15m | LV `authn_login_fail`; ATT T1078 |
| A6 | New country / impossible travel | Login from a country never seen for that user, or two places too far apart too fast | Successful logins + IP geolocation | [M] any new country; > ~900 km/h | ✅ 15m | AS AE13; LV `authn_impossible_travel`; ATT T1078 |
| A7 | Session hijack signs | IP or user agent changes mid-session; expired session or revoked token reused | Request log by session | [M] ≥ 1 (privileged users: always) | ○ | AS SE4, SE5, SE6; LV `session_use_after_expire`, `authn_token_reuse`; ATT T1539, T1550 |
| A8 | Forced browsing / 404 burst | Path guessing with a wordlist | 404s by IP | [M] ≥ 50 404s or ≥ 20 distinct missing paths per IP in 15m | ✅ 15m | AS ACE3; LV `malicious_excess_404`; ATT T1595.003; OAT-014 |
| A9 | Scanner fingerprint | Attack-tool user agents; probes for `/.env`, `/.git/config`, `/wp-admin`; odd methods | User agent, path, method | [M] ≥ 1 (once per IP per day) | ✅ 15m | LV `malicious_attack_tool`; AS RE1, RE2; ATT T1595.002; OAT-018 |
| A10 | Injection attempts | XSS / SQL injection payloads | WAF deny/challenge on managed rules; validation errors | [M] ≥ 1 that reached the app with a 5xx; ≥ 10 blocked per IP | ○ | AS IE1, IE3, CIE1; LV `malicious_sqli`, `input_validation_fail`; ATT T1190 |
| A11 | Firewall action surge | Abnormal deny / challenge / rate_limit volume | Drain `proxy.wafAction` | [M] > 3× baseline or > 500 in 15m | ✅ 15m | LV `excess_rate_limit_exceeded`; ATT T1499.003 |
| A12 | Authorization failures / IDOR | A logged-in user probing objects they don't own | 403s per user | [M] ≥ 10 per user in 15m | ○ | AS ACE1, ACE2, ACE4; LV `authz_fail`, `malicious_direct_reference` |
| A13 | Abnormal data volume / scraping | Unusual records or bytes per user | `proxy.responseByteSize` per user | [M] > 10× the user's 30-day p95 | ○ | AS CIE2, UT2, UT4; ATT T1213; OAT-011 |
| A14 | Honeytrap hit | A decoy path no legitimate client uses | Request log | [M] ≥ 1 | ○ | AS HT2, HT3; ATT T1595 |
| A15 | 5xx spike | Errors from exploitation or exhaustion | Drain status ≥ 500 | [M] > 3× baseline | ○ | LV `sys_crash`; ATT T1499.003 |

## B. Accounts and identity (15m)

| # | Detection | What it detects | Signal | Threshold | Status | Source |
|---|---|---|---|---|---|---|
| B1 | App privilege change | User made admin, role changed, user created | App users/roles table | ≥ 1 | ○ | LV `authz_change`, `authz_admin`, `user_created`; ATT T1098 |
| B2 | Login by an offboarded user | Success for a user suspended or missing in the directory | Logins + Google Directory `suspended` | ≥ 1 | ○ | CIS Controls 6.2; ATT T1078 |
| B3 | GitHub member / role change | Owner promoted, member invited, outside collaborator added | `org.update_member`, `org.add_member`, `org.invite_member`, `org.add_outside_collaborator`; webhooks `organization`, `member` | ≥ 1 | ○ | GH-AUD; GH-WH; ATT T1098, T1136.003, T1199 |
| B4 | GitHub 2FA requirement disabled | Org-wide 2FA turned off | `org.disable_two_factor_requirement` | ≥ 1 | ○ | GH-AUD; CIS Controls 6.3, 6.5 |
| B5 | GitHub token granted | Fine-grained PAT granted; flag access to all repos | `personal_access_token.access_granted`, `.request_created` | ≥ 1 | ○ | GH-AUD; ATT T1528, T1098.001 |
| B6 | Vercel team change | Access request, member added or removed, role changed | Team members API + audit events | ≥ 1 | ✅ D (15m ○) | VC-AUD; ATT T1098 |
| B7 | AWS root use | Root credentials used | CloudTrail `userIdentity.type = Root`; GuardDuty `Policy:IAMUser/RootCredentialUsage` (Low) | [S] ≥ 1 | ✅ 15m | CIS v5 4.3 / CloudWatch.1; GD-IAM |
| B8 | AWS console sign-in risk | Console login without MFA; console auth failures | `ConsoleLogin` with `MFAUsed != Yes`; `Failed authentication` | [S] ≥ 1 ([M] ≥ 3 in 15m for failures) | ✅ 15m | CIS v5 4.2, 4.6 (CloudWatch.3, .6) |
| B9 | AWS unauthorized API calls | Calls rejected for permissions | `*UnauthorizedOperation`, `AccessDenied*` | [S] ≥ 1; [M] ≥ 10 per principal in 15m | ✅ 15m | CIS v5 4.1 / CloudWatch.2 |
| B10 | New IAM identity or key | IAM user, login profile or access key created | CloudTrail CreateUser / CreateLoginProfile / CreateAccessKey; GuardDuty `Persistence:IAMUser/AnomalousBehavior` | ≥ 1 | ✅ 15m | ATT T1136.003, T1098.001; GD-IAM |
| B11 | Stolen AWS credentials | Exfiltrated keys, Tor or malicious IPs, pentest distros | GuardDuty `CredentialAccess:IAMUser/CompromisedCredentials`, `InstanceCredentialExfiltration.OutsideAWS`, `*/TorIPCaller`, `*/MaliciousIPCaller`, `PenTest:IAMUser/KaliLinux` | ≥ 1, any severity | ✅ 15m | GD-IAM; ATT T1078.004, T1552.005 |
| B12 | Database logins | Anomalous, brute-forced, Tor or malicious-IP logins to RDS | GuardDuty `CredentialAccess:RDS/*`, `Discovery:RDS/*` | ≥ 1, **including Low** | ✅ 15m | GD-RDS; ATT T1110, T1078 |

## C. Cloud and infra changes (15m)

| # | Detection | What it detects | Signal | Threshold | Status | Source |
|---|---|---|---|---|---|---|
| C1 | CloudTrail tampering | Trail deleted, stopped or changed | Create/Update/DeleteTrail, StopLogging, PutEventSelectors; GuardDuty `Stealth:IAMUser/CloudTrailLoggingDisabled` | [S] ≥ 1 | ✅ 15m | CIS v5 4.5 / CloudWatch.5; ATT T1562.008 |
| C2 | IAM or password policy change | Policies attached/changed; password policy weakened | IAM Put/Delete/Attach/Detach*Policy, CreatePolicyVersion…; GuardDuty `Stealth:IAMUser/PasswordPolicyChange` | [S] ≥ 1 | ✅ 15m | CIS v5 4.4 / CloudWatch.4; ATT T1098.003 |
| C3 | KMS key disabled or scheduled for deletion | Key made unusable | DisableKey, ScheduleKeyDeletion | [S] ≥ 1 | ✅ 15m | CIS v5 4.7 / CloudWatch.7; ATT T1485 |
| C4 | S3 policy / public exposure | Bucket policy, ACL or public access opened | S3 Put/Delete Bucket*; GuardDuty `Policy:S3/*`, `Stealth:S3/ServerAccessLoggingDisabled` | [S] ≥ 1 | ✅ 15m | CIS v5 4.8 / CloudWatch.8; GD-S3; ATT T1530 |
| C5 | AWS Config change | Recorder stopped, delivery channel deleted | StopConfigurationRecorder, DeleteDeliveryChannel | [S] ≥ 1 | ✅ 15m | CIS v5 4.9 / CloudWatch.9; ATT T1562.008 |
| C6 | Network change | Security group, NACL, gateway, route table or VPC changed; escalate if 0.0.0.0/0 opens a database or admin port | CloudTrail EC2 events | [S] ≥ 1 | ✅ 15m | CIS v5 4.10–4.14 / CloudWatch.10–14; EC2.53, EC2.54 |
| C7 | Organizations change | Changes to the AWS Organization | organizations events | [S] ≥ 1 | ✅ 15m | CIS v5 4.15 |
| C8 | Detector disabled | Security Hub or GuardDuty turned off | CloudTrail / API state | ≥ 1 | ✅ 15m | CIS v5 4.16 (Security Hub); GuardDuty part [M] |
| C9 | Database made public / snapshot exfiltration | RDS public; snapshot or restore by an anomalous principal | RDS.2; GuardDuty `Exfiltration:IAMUser/AnomalousBehavior` | ≥ 1 | ◐ snapshots and public RDS, 15m | CIS v5 2.2.3 / RDS.2; ATT T1537 |
| C10 | Database theft or destruction | Mass SELECT, DROP or DELETE | GuardDuty `Exfiltration:RDS/*`, `Impact:RDS/*` | ≥ 1 | ✅ 15m | GD-RDS; ATT T1213, T1485 |
| C11 | Secrets changed or read | Vercel env vars added/changed/pulled; GitHub Actions secrets changed | Vercel audit events; `org.update_actions_secret` | [M] ≥ 1 outside a deploy | ◐ Vercel, daily | VC-AUD; GH-AUD; ATT T1552 |
| C12 | Protection, domain or project moved | Preview protection off, DNS changed, domain or project moved out | Vercel audit events / snapshot diff | ≥ 1 | ◐ protection events, daily | VC-AUD |
| C13 | Log source went silent | A drain, CloudTrail or webhook feed stops sending | Last event per source | [M] > 30 min (prod drain), > 2h (CloudTrail) | ✅ 15m | LV `sys_monitor_disabled`; ATT T1562.008 |

## D. Code and supply chain (events 15m, state D)

| # | Detection | What it detects | Signal | Threshold | Status | Source |
|---|---|---|---|---|---|---|
| D1 | Repo made public | Visibility change | `repo.access`; webhook `repository.publicized` | ≥ 1, top priority | ○ | GH-AUD; ATT T1213.003 |
| D2 | Branch protection weakened | Protection or ruleset removed, admin override | `protected_branch.destroy`, `.policy_override`, `repository_ruleset.*` | ≥ 1 | ○ | GH-AUD; ATT T1195.002 |
| D3 | Deploy key added | New key with repo access; flag write access | `public_key.create`; webhook `deploy_key` | ≥ 1 | ○ | GH-AUD; ATT T1098.001 |
| D4 | App installed with broad access | GitHub App / OAuth app; flag access to all repos | `integration_installation.*`, `oauth_application.create` | ≥ 1 | ○ | GH-AUD; ATT T1199, T1528 |
| D5 | New webhook | Possible exfiltration channel | `hook.create` | ≥ 1 | ○ | GH-AUD; ATT T1567.004 |
| D6 | Secret leaked | Secret scanning alert; flag publicly leaked | `secret_scanning_alert.create` | ≥ 1 | ○ (R4/R5 cover committed files) | GH-AUD; ATT T1552.001 |
| D7 | Secret controls bypassed | Push protection bypassed or disabled | `secret_scanning_push_protection.bypass`, `repository_secret_scanning.disable` | ≥ 1 | ○ | GH-AUD |
| D8 | Critical dependency | New Dependabot alert (critical at once, the rest daily) | webhook `dependabot_alert` | ≥ 1 critical | ○ (R1 covers Radar advisories) | GH-AUD; ATT T1195.001 |
| D9 | Repo deleted or transferred | Repo destroyed or moved out | `repo.destroy`, `repo.transfer` | ≥ 1 | ○ | GH-AUD; ATT T1485, T1537 |
| D10 | Mass clone | One actor cloning many repos | `git.clone` (Enterprise) | [M] ≥ 10 repos per actor per hour | ○ | GH-AUD; ATT T1213.003 |

## E. Hygiene KPIs (daily)

| # | KPI | Signal | Threshold | Status | Source |
|---|---|---|---|---|---|
| E1 | Dormant accounts, and accounts that log in but do nothing | Last login and last real action per user; Google `lastLoginTime` | [S] 45 days with no activity. [M] idle: sessions but zero business actions in 30 days | ✅ D (vigía) | CIS Controls 5.3 |
| E2 | Accounts without MFA | Google `isEnrolledIn2Sv`; IAM credential report `mfa_active`; GitHub org 2FA | target 0 | ◐ Vercel only (`vercel security check`), D | CIS Controls 6.3, 6.5; CIS v5 1.9 / IAM.5 |
| E3 | AWS root hygiene | Root access key, root MFA, hardware MFA | 0 deviations | ◐ via Security Hub | CIS v5 1.3–1.5 (IAM.4, IAM.9, IAM.6) |
| E4 | Stale access keys | Credential report `access_key_N_last_rotated`; > 1 active key | [S] > 90 days; > 1 key | ○ | CIS v5 1.13 / IAM.3; 1.12 |
| E5 | Unused credentials | `password_last_used`, `access_key_N_last_used_date` | [S] ≥ 45 days | ○ | CIS v5 1.11 / IAM.22 |
| E6 | Offboarding drift | People in GitHub, Vercel, AWS or the app who are missing or suspended in the directory | 0. [S] at least quarterly; [M] daily | ○ | CIS Controls 6.2, 5.1 |
| E7 | Privileged account count | Google admins, GitHub owners, Vercel owners, IAM `*:*` | [M] alert on any increase | ○ | CIS Controls 5.4, 6.8; CIS v5 1.14, 1.15 |
| E8 | Non-human access inventory | PATs, all-repo apps, deploy keys, outside collaborators, IAM keys | [S] review quarterly | ◐ Vercel only (`vercel security check`), D | CIS Controls 5.5 |
| E9 | Logging coverage and retention | CloudTrail multi-region and validation, Config, flow logs, drains per Vercel project | [S] retention ≥ 90 days; GitHub keeps only 180, so export it | ○ | CIS v5 3.1–3.9; CIS Controls 8.2, 8.9, 8.10 |
| E10 | Infra posture drift | Public or unencrypted RDS; ports open to the world | 0 failing controls | ◐ via Security Hub | CIS v5 2.2.1–2.2.3, 5.2–5.4 |
| E11 | Repo security coverage | Branch protection, secret scanning, Dependabot on every repo | [M] 100% | ○ | GH-WH (`security_and_analysis`) |
| E12 | Open vulnerabilities by severity and age | Inspector, Security Hub, Dependabot | [S] remediate monthly or faster, by risk | ◐ Inspector and Security Hub | CIS Controls 7.2, 7.7; NIST55 |

## F. Program metrics (weekly / monthly)

| # | Metric | How to compute it here | Status | Source |
|---|---|---|---|---|
| F1 | MTTD (time to detect) | Event time → hackme alert | ○ | NIST55 §4.4 |
| F2 | MTTA (time to acknowledge) | Telegram alert → human reply | ○ | common SOC practice; no standard source verified |
| F3 | MTTR (time to recover) | Alert → resolved | ○ | NIST55 §4.4 |
| F4 | Remediation time vs. SLA by severity | First seen → fixed | ○ | NIST55 §3; CIS Controls 7.7 |
| F5 | % of assets monitored | Repos, Vercel projects with drains, AWS regions with GuardDuty, over the inventory | ○ | NIST55 Table 4 |
| F6 | % patched | Repos with no open critical/high, over all repos | ○ | NIST55 Table 4 |
| F7 | Secret exposure time | Secret found → rotated | ○ | [M] derived |
| F8 | Mean age of open critical findings | Average age of unresolved critical/high | ○ | [M] derived |
| F9 | False-positive rate, and weekly review done | Alerts closed as benign ÷ all alerts | ○ | NIST55 §4.4; CIS Controls 8.11 |

## What the vigía does (built)

[vigia.md](vigia.md). Every 15 minutes: **A1–A6, A8, A9, A11** on your apps' request log and login
events, **C13** when that log goes silent, and on AWS **B7–B12, C1–C8, C10** from CloudTrail and
GuardDuty at any severity. Once a day: **E1** (dormant accounts, and accounts that log in and do
nothing when the app records actions).

Next: A7 (session hijack signs), A12 (authorization probing), A13 (scraping), the GitHub rows (D)
and the hygiene KPIs (E2–E12).

## Verification notes

- AppSensor IDs come from the archived OWASP wiki; the v2 guide PDF was not re-read.
- CIS AWS v5/v3 numbering comes from Turbot's steampipe compliance mod and AWS's CIS mapping table;
  the CIS PDF itself was not accessed.
- T1562.008 was confirmed through search results pointing to its ATT&CK page (the page fetched
  empty).
- Not verified: the IAM event names in B10, the event names for C8, Vercel firewall config change
  events, a standard source for MTTA.

## Sources

- [AS] OWASP AppSensor detection points — https://wiki.owasp.org/index.php/AppSensor_DetectionPoints
- [LV] OWASP Logging Vocabulary — https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html
- OWASP Logging Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- [OAT] OWASP Automated Threats — https://github.com/OWASP/www-project-automated-threats-to-web-applications/tree/master/assets/oats/EN
- [ATT] MITRE ATT&CK — https://attack.mitre.org/techniques/ (T1078, T1098, T1110, T1136, T1190, T1195, T1199, T1213, T1485, T1499, T1528, T1530, T1537, T1539, T1550, T1552, T1562/008, T1567, T1595)
- [NIST63B] NIST SP 800-63B-4 — https://pages.nist.gov/800-63-4/sp800-63b.html
- [NIST55] NIST SP 800-55 Vol. 1 — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-55v1.pdf
- AWS Security Hub CIS mapping — https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html
- AWS Security Hub CloudWatch controls — https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html
- CIS AWS v5 / v3 control titles (Turbot) — https://github.com/turbot/steampipe-mod-aws-compliance/tree/main/cis_v500
- [GD-IAM] GuardDuty IAM findings — https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html
- [GD-S3] GuardDuty S3 findings — https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html
- [GD-RDS] GuardDuty RDS findings — https://docs.aws.amazon.com/guardduty/latest/ug/findings-rds-protection.html
- IAM credential report — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html
- [GH-AUD] GitHub org audit log events — https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization
- [GH-WH] GitHub webhook events — https://docs.github.com/en/webhooks/webhook-events-and-payloads
- [VC-AUD] Vercel audit logs — https://vercel.com/docs/audit-log
- [VC-DR] Vercel log drain schema — https://vercel.com/docs/drains/reference/logs
- Google Directory API users — https://developers.google.com/workspace/admin/directory/reference/rest/v1/users
- CIS Controls v8 — https://cas8.docs.cisecurity.org/en/latest/source/Controls5/ (and Controls6, 7, 8)
