# Metasploit — self-hosted lab exercise (isolated, never against third parties)

Metasploit is an offensive exploitation framework. The only legitimate way to
build hands-on experience with it is a **deliberately vulnerable target you run
yourself, on an isolated network**. This runbook sets that up. Nothing here is
aimed at any system you do not own; do not run Metasploit against the internet,
a shared network, or any host without written authorization — doing so is a
crime regardless of intent.

## Lab setup (host-only network, no internet bridge)

1. Install the framework: `brew install metasploit` (or the official installer).
   Start the DB: `msfdb init`.
2. Target: run an intentionally-vulnerable VM in a **host-only** network so it
   can reach only your machine. Standard teaching targets:
   - Metasploitable 2/3 (purpose-built vulnerable Linux)
   - OWASP Juice Shop (web, for the app-layer work; pairs with the Burp runbook)
   - A Docker `vulhub` scenario for a specific CVE
3. Verify isolation: the target must not reach the internet and nothing outside
   the lab must reach the target. Confirm with `nmap` from the host only.

## Exercises (on the lab target only)

| Phase | Tooling | Skill demonstrated |
|---|---|---|
| Recon | `db_nmap` into msf | service/version enumeration, workspace notes |
| Select | `search`, `use` | mapping a service version to a module |
| Exploit | module `run` | configuring RHOSTS/LHOST, getting a session |
| Post | meterpreter | understanding what post-exploitation reveals (so you can defend it) |
| Report | workspace export | a findings write-up with remediation |

## Why it's in this toolkit

The point for a defender is the *other side of the table*: running these modules
against a lab target teaches what the artifacts of an intrusion look like, which
is what you then write detections and hardening for. Keep the lab notes in this
folder; keep the lab offline.

## Honest status

This is the one bullet-area the toolkit does **not** automate or run for you — it
requires a VM and an isolated network you set up by hand. The runbook is the plan;
doing the lab is a half-day exercise. The other three tool areas (Semgrep,
fuzzing, prompt-injection) are wired into the real projects and runnable now.
