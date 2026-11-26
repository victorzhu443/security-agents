# semgrep/ — custom SAST rules

`rules.yml` holds the project-specific rules; `scan.sh` runs them together with
the registry packs (`p/python`, `p/secrets`, plus `p/django` / `p/owasp-top-ten`
for the web apps). Every rule has a positive and a negative fixture in
`tests/test_rules.py`, which runs the real `semgrep` binary.

```bash
semgrep --validate --config semgrep/rules.yml          # schema + lint
python -m pytest tests/test_rules.py -q                # fixtures
semgrep/scan.sh ../firstplay/firstplay-backend         # a real scan
```

Rules are Python-only. Semgrep notes that matter when editing them:
`metavariable-regex` is anchored at the start of the bound text (write
`^(.*\.)?name$`, not `(^|\.)name$`); `pattern-not` inside a
`metavariable-pattern` cannot suppress a call, because `pattern: $X` also
matches the call's sub-expressions; a `"$K"` pattern binds `$K` to the string's
contents.

## Rule coverage

| Rule | Severity | Catches | Known limits |
|---|---|---|---|
| `untrusted-text-into-prompt-sink` | WARNING | An f-string whose interpolated name looks untrusted (`text`, `content`, `document`, `page`, `chunk`, `body`, `source`, `passage`, `snippet`, `html`, `paper`, `user_input`, `answer`, `summary`) placed in a `"content":` dict entry, `content=` kwarg, `HumanMessage(...)`, or `$PROMPT.format(k=v)`. OWASP LLM01 / CWE-74. | Keyed on the *value's* name, so `f"...{x}..."` with a bland name is missed. Does not see templated prompts (next two rules). No taint tracking: a value hardened on a previous line still fires. |
| `untrusted-placeholder-bound-unhardened` | WARNING | A LangChain bind site where an untrusted-looking *key* (the list above plus `job_text`, `resume_text`, `query`) is bound to a raw value: `X.invoke({...})`, `.ainvoke`, `.stream`, `.batch([{...}])`, `.invoke(input={...})`, `tmpl.format(**{...})`, `tmpl.format_messages(k=v)` / `.format_prompt` / `.format`, and the project wrappers `invoke_chain(chain, {...})` / `invoke_with_retry(factory, {...})`. The callee is matched by name (`^(.*\.)?(a?invoke\|a?batch\|a?stream\|invoke_chain\|invoke_with_retry\|a?format\|a?format_messages\|a?format_prompt)$`). The finding points at the value. | A value is exempt when it is a string literal or *is* a call to `harden(...)`, `harden_untrusted(...)`, `Untrusted(...)` or `build_prompt(...)` (optionally module-qualified or parenthesised); a hardening call nested deeper (`a if ok else harden(a)`, `prefix + harden(a)`) does not exempt it. Only literal dicts are seen: `chain.invoke(payload)` with a variable, a dict built on an earlier line, a comprehension in `.batch([... for ...])`, or a nested dict (`{"input": {"job_text": x}}`) is opaque. Keys are a name heuristic: model-derived values bound under other names (`resume_data`, `required_skills`) are second-order injection and are not flagged. Overlaps the first rule on `.format(k=v)` when both the key and the value have untrusted names. |
| `untrusted-placeholder-in-prompt-template` | INFO | A prompt template whose text contains an `{...}` placeholder with an untrusted-looking name: `X.from_messages([("role", "...")])` (the string may be concatenated with a constant on either side), `from_messages(["...", X.from_template("...")])`, `X.from_template("...")`, `X(template="...")`. A review aid: the message tells the reader to confirm the bind site hardens the value. | Not a finding by itself; a template whose bind site hardens the value still reports here. Template text must be a string literal in the call; a template loaded from a file or built by `"".join` is invisible. Same name heuristic as above. |
| `subprocess-shell-true` | ERROR | `subprocess.run/Popen/call(..., shell=True)` and `os.system(...)`. CWE-78. | Fires even when the command is a constant. |
| `yaml-unsafe-load` | ERROR | `yaml.load($X)` with a single argument. CWE-502. | `yaml.load(x, Loader=yaml.Loader)` (two arguments) is not matched. |
| `pickle-load-untrusted` | WARNING | Any `pickle.load` / `pickle.loads`. CWE-502. | Cannot tell trusted bytes from downloaded ones; triage by source. |
| `requests-verify-disabled` | ERROR | `requests.<method>(..., verify=False)`. CWE-295. | A `Session` with `session.verify = False` is not matched. |
| `sql-string-format` | ERROR | `cursor.execute(f"...")`, `execute("..." % ...)`, `execute("..." + x)`. CWE-89. | A query string built on an earlier line and passed as a variable is not matched. |
| `eval-exec-call` | ERROR | Any `eval(...)` / `exec(...)`. CWE-95. | Fires on constant arguments too. |
| `django-debug-true` | WARNING | `DEBUG = True`. CWE-489. | Matches in any module, not only settings. |
| `hardcoded-secret-assignment` | ERROR | `NAME = "..."` where the name contains `api_key`, `apikey`, `secret`, `password`, `passwd`, `token`, `private_key`, `aws_secret`, and does not contain `EXAMPLE`, `PLACEHOLDER` or `os.environ`. CWE-798. | The exclusion regex is applied to the variable name, not the value; an empty or placeholder *value* still fires. Attribute and dict assignments are not matched. |
| `weak-hash-non-crypto` | WARNING | `hashlib.sha1(...)` / `hashlib.md5(...)` without `usedforsecurity=False`. CWE-328. | `hashlib.new("md5")` is not matched. |
| `torch-load-unsafe` | WARNING | `torch.load(...)` without `weights_only=True`. CWE-502. | None beyond the kwarg check. |
| `flask-dev-bind-all` | WARNING | `app.run(..., host="0.0.0.0", ...)`. CWE-668. | A host read from config is not matched. |

## The two halves of a templated prompt

The f-string rule sees the prompt being built. A LangChain template splits that
into a template that declares `{job_text}` and a bind site that supplies the
value later, often through a project wrapper rather than `chain.invoke`
directly. The INFO rule marks the template so a reviewer knows a bind site
exists; the WARNING rule is the finding at the bind site. On firstplay the pair
reads as: `job_parser.py` template flagged INFO, its bind site quiet because the
value is `harden_untrusted(job_text)`; `resume_parser.py` template flagged INFO
and its bind site flagged WARNING because `resume_text` is bound raw.
