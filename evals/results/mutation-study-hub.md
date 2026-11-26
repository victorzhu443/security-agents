# Mutation testing — study-hub @ 39dfa7fc4bbd

Mutations: 11 · killed: 11 · survived: 0 · errors: 0

**Kill rate 1.0**

Baseline (unmutated) exit 0 in 6.4s — green

| property | mutations | killed | survived | errors | kill rate |
|---|---|---|---|---|---|
| P1 | 1 | 1 | 0 | 0 | 1.0 |
| P2 | 6 | 6 | 0 | 0 | 1.0 |
| P4 | 2 | 2 | 0 | 0 | 1.0 |
| P5 | 1 | 1 | 0 | 0 | 1.0 |
| P9 | 1 | 1 | 0 | 0 | 1.0 |

| id | property | result | seconds | description |
|---|---|---|---|---|
| P1-ledger-no-containment | P1 | killed | 6.3 | ledger writes join root/relpath without contained_path (path traversal, 3fcc877) |
| P2-redact-ambiguous-prefix | P2 | killed | 4.5 | cookie-header regex back to the step-1 form `[ \t]*-?[ \t]*` (quadratic on space runs, bb2a1b5) |
| P2-xlsx-read-before-size-check | P2 | killed | 6.2 | sharedStrings.xml decompressed in full before any size check (a0a4155) |
| P2-xlsx-unsafe-xml-parse | P2 | killed | 6.4 | parse sharedStrings.xml with stdlib ElementTree, entities expanded unbounded (billion laughs, 3fcc877) |
| P2-piazza-strip-html-quadratic-tag-regex | P2 | killed | 13.5 | strip_html tag regex back to `<[^>]+>`, which rescans to the end from every `<` (a0a4155) |
| P2-html-to-md-trailing-blank-regex | P2 | killed | 8.7 | html_to_md trims trailing blanks with `[ \t]+\n` again (0.15 s at 10k chars, 2.3 s at 40k; a0a4155) |
| P2-ed-attachment-uncapped-body | P2 | killed | 0.5 | Ed attachment download reads the whole body with no Content-Length gate (a0a4155) |
| P4-fetch-no-allowlist | P4 | killed | 0.6 | safe_http.fetch stops applying the hub-derived host allow-list (any public host is fetched, 5f688bf) |
| P4-piazza-links-no-host-check | P4 | killed | 6.4 | resource_links follows any href lifted from the fetched Resources page with the user's session (a0a4155) |
| P5-gradescope-session-default-umask | P5 | killed | 6.4 | gradescope-cookies.json written with write_text at the process umask (0644) instead of write_private (a0a4155) |
| P9-sha1-security-default | P9 | killed | 6.3 | announcement id hash drops usedforsecurity=False (5f688bf) |
