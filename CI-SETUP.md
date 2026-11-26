# CI setup — one reusable security workflow for every repo

Every project repo runs the same three jobs (DESIGN.md §2.3): `security-tests`
(`pytest tests/security`), `sast` (Semgrep with the toolkit's rules, plus bandit)
and `sca` (`pip-audit --strict`). They live once, in this repo, as
[`.github/workflows/security-reusable.yml`](.github/workflows/security-reusable.yml).
A project repo calls it with a 12-line workflow and a secret. This file is the
one-time setup, written for Victor to do by hand; nothing here is automated.

**Why a secret at all.** This repo is private: it documents findings that are not yet
fixed in the apps (ROOT-CAUSES.md, DESIGN.md). A project repo's `GITHUB_TOKEN` is
scoped to that repo, so it can *run* the reusable workflow once access is allowed
(step 2) but cannot *read* this repo's contents: the Semgrep rules, `secprim`, the
`git+https://…security-agents@v0.1.1` pin in `requirements.txt`. Those need a token
that can read this repo. The workflow fetches everything with one secret,
`TOOLKIT_TOKEN`, and checks the toolkit out at the exact commit the caller's `@ref`
points to, so rules and package never drift from the pin.

## 1. In this repo, once: release the workflow

The reusable workflow has to exist at the ref the callers pin. `v0.1.0` predates it.

```bash
cd ~/Developer/projects/security-agents
git checkout main && git pull
git tag -a v0.1.1 -m "Reusable security workflow (tests, SAST, SCA); templates; CI-SETUP"
git push origin v0.1.1
```

## 2. In this repo, once: allow other repos to call the workflow

A private repo's workflows are callable only after this is switched on. Either:

- **UI:** `github.com/victorzhu443/security-agents` → *Settings* → *Actions* →
  *General* → section **Access** → choose **"Accessible from repositories owned by
  the user 'victorzhu443'"** → *Save*.
- **CLI:**
  ```bash
  gh api -X PUT repos/victorzhu443/security-agents/actions/permissions/access -f access_level=user
  gh api repos/victorzhu443/security-agents/actions/permissions/access   # confirm: "access_level": "user"
  ```

This lets a caller's `GITHUB_TOKEN` fetch the workflow *file*. It does not grant
access to the repo's contents; that is what step 3 is for.

## 3. Once: create the token

GitHub → profile *Settings* → *Developer settings* → *Personal access tokens* →
**Fine-grained tokens** → *Generate new token*:

| Field | Value |
|---|---|
| Token name | `security-agents-ci-read` |
| Expiration | pick one (fine-grained tokens cap at a year); put the renewal date in the calendar |
| Resource owner | `victorzhu443` |
| Repository access | **Only select repositories** → `security-agents` |
| Repository permissions | **Contents: Read-only** (Metadata: Read-only is added automatically) |

Everything else stays "No access". Copy the token once; it is not shown again.
Never paste it into a file in any repo.

## 4. Per project repo: add the secret

For each of `research-replication-agent`, `firstplay-backend`, `smart-dispatch`,
`study-hub` (the repo names on GitHub):

```bash
gh secret set TOOLKIT_TOKEN -R victorzhu443/<repo>     # prompts; paste the token
```

or *repo Settings* → *Secrets and variables* → *Actions* → *New repository secret*,
name `TOOLKIT_TOKEN`.

A repo whose workflow already names the secret `GH_PAT` can keep that name: the
caller maps it with `TOOLKIT_TOKEN: ${{ secrets.GH_PAT }}`.

## 5. Per project repo: drop in the two files

```bash
cp ~/Developer/projects/security-agents/templates/security.yml   <repo>/.github/workflows/security.yml
cp ~/Developer/projects/security-agents/templates/dependabot.yml <repo>/.github/dependabot.yml
```

Then fill `with:` in `security.yml`. Inputs (all optional):

| Input | Default | Meaning |
|---|---|---|
| `python-version` | `"3.11"` | for every job |
| `requirements` | `""` | requirements file: installed before the tests, audited by `sca` (VCS/local/toolkit lines filtered out) |
| `source-dirs` | `"."` | space-separated dirs for Semgrep and bandit |
| `semgrep-extra-configs` | `""` | e.g. `"p/django p/owasp-top-ten"` |
| `tests-path` | `"tests/security"` | passed to pytest |
| `tests-env` | `""` | `KEY=VALUE` lines exported before pytest |
| `install-cmd` | `""` | replaces `pip install -r <requirements>` for the tests; when `requirements` is empty, also builds the environment `sca` audits |
| `bandit-skips` | `""` | bandit test ids to skip, with the reason in a comment |
| `audit-ignore` | `"audit-ignore.toml"` | accepted-risk list (section 6) |

Secret: `TOOLKIT_TOKEN`. In `dependabot.yml`, delete the `npm` block in a repo with
no `package.json`, or point its `directory` at the frontend folder.

Starting points per repo, matching what each repo's draft `security.yml` does today:

| Repo | `with:` |
|---|---|
| research-replication-agent (uv, 3.12) | `python-version: "3.12"`, `requirements: ""`, `install-cmd: pip install uv && uv export --frozen --no-hashes --no-emit-project -o requirements-lock.txt && pip install -r requirements-lock.txt -e .`, `tests-env: REPLICATOR_SANDBOX_BACKEND=local`, `source-dirs: replicator` |
| smart-dispatch (Django) | `requirements: requirements.txt`, `install-cmd: pip install -r requirements_minimal.txt Django sqlalchemy hypothesis`, `semgrep-extra-configs: "p/django p/owasp-top-ten p/kubernetes"`; move the `--ignore-vuln` ids into `audit-ignore.toml` with `expires = 2026-12-31` |
| study-hub | `requirements: requirements.txt`, `tests-path: tests` |
| firstplay-backend | `requirements:` its requirements file, `semgrep-extra-configs: "p/owasp-top-ten"` plus the framework pack |

Commit, push, and watch the first run (`gh run watch -R victorzhu443/<repo>`). Three
jobs appear under `security /`: `security-tests`, `sast`, `sca`. Any finding fails;
that is the point.

## 6. Accepted risks: `audit-ignore.toml`

`sca` fails on any known vulnerability. A risk that is understood and cannot be fixed
yet goes in `audit-ignore.toml` at the repo root (template:
[`templates/audit-ignore.toml`](templates/audit-ignore.toml)):

```toml
[[ignore]]
id = "PYSEC-2024-271"
reason = "flask-cors 4 -> 6 is a major; lands in the dedicated majors PR"
expires = 2026-12-31
```

Each entry needs `id`, `reason` and `expires`. The job passes `--ignore-vuln <id>` to
pip-audit for every entry whose `expires` is today or later, and **fails** the moment
an entry is past its date, naming it. An expiry is extended only by editing the file
in a PR, so the extension is itself reviewed. Nothing is accepted silently or forever.

## 7. When the toolkit releases

Tag here (`git tag -a v0.1.2 …; git push origin v0.1.2`), then bump the ref in each
caller: `uses: victorzhu443/security-agents/.github/workflows/security-reusable.yml@v0.1.2`
and, where present, the `security-agents@v0.1.2` pin in `requirements.txt`. The two
move together; the workflow installs and scans with the commit its own `@ref` names.
Dependabot's `github-actions` ecosystem proposes the `uses:` bump automatically.

Built tags are immutable: never move a tag, cut the next one.

## 8. Without a PAT: make the toolkit public

Then every step above but 5 disappears: the callers' `GITHUB_TOKEN` reads a public
repo, `pip` clones it without credentials, and the `secrets:` block in `security.yml`
can be deleted (the workflow falls back to `github.token`).

The repo is private for now because ROOT-CAUSES.md and DESIGN.md describe concrete,
unfixed weaknesses in the apps, with file and line. Making it public is right once the
fixes those documents plan have merged in each repo; until then the PAT is the cost of
keeping the findings off the public record.
