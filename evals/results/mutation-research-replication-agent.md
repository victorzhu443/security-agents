# Mutation testing — research-replication-agent @ 314f8043e797

Mutations: 18 · killed: 18 · survived: 0 · errors: 0

**Kill rate 1.0**

Baseline (unmutated) exit 0 in 11.2s — green

| property | mutations | killed | survived | errors | kill rate |
|---|---|---|---|---|---|
| P1 | 2 | 2 | 0 | 0 | 1.0 |
| P2 | 3 | 3 | 0 | 0 | 1.0 |
| P3 | 6 | 6 | 0 | 0 | 1.0 |
| P4 | 3 | 3 | 0 | 0 | 1.0 |
| P5 | 2 | 2 | 0 | 0 | 1.0 |
| P8 | 2 | 2 | 0 | 0 | 1.0 |

| id | property | result | seconds | description |
|---|---|---|---|---|
| P3-sandbox-env-inherits-parent | P3 | killed | 0.9 | child env built from os.environ (inherit-minus-denylist) instead of the allow-list |
| P3-rlimits-not-applied | P3 | killed | 0.9 | no preexec_fn, so RLIMIT_CPU/NPROC/FSIZE/AS are never set in the child (the pre-fix macOS state) |
| P3-rss-watchdog-disabled | P3 | killed | 26.3 | memory is unbounded in local mode (RLIMIT_AS is advisory on macOS; the watchdog was the fix) |
| P3-timeout-kills-only-the-child | P3 | killed | 32.1 | on timeout kill the direct child, not the process group (grandchildren survive) |
| P3-container-network-open | P3 | killed | 7.8 | container backend always gets a bridge network instead of --network none |
| P3-local-banner-not-logged | P3 | killed | 11.3 | the run log no longer says which execution boundary the run got (silent local mode) |
| P5-scrub-secrets-noop | P5 | killed | 10.7 | scrub_secrets returns the env unchanged (the orchestrator's LLM credentials pass through) |
| P5-secret-looking-extra-accepted | P5 | killed | 6.3 | no assert_no_secrets check, so a caller can hand a token to generated code via extra |
| P1-run-python-path-unchecked | P1 | killed | 2.0 | the builder's run_python tool takes the model's path as-is (no contained_path) |
| P1-runner-parquet-side-file-is-a-path | P1 | killed | 2.0 | a sandboxed result may name a parquet side file by path, reading outside the work dir |
| P4-arxiv-allowlist-dropped | P4 | killed | 2.0 | fetch_arxiv follows redirects to any host (no arxiv.org allow-list) |
| P4-html-body-uncapped | P4 | killed | 2.0 | fetch_html_as_text reads an unbounded body (the pre-fix httpx.get behaviour) |
| P4-french-allowlist-dropped | P4 | killed | 2.0 | the French-library download follows redirects off mba.tuck.dartmouth.edu |
| P2-french-zip-unbudgeted | P2 | killed | 2.0 | zip members are read without the declared-size / ratio budget (zip-bomb) |
| P2-html-tag-regex-quadratic | P2 | killed | 3.4 | the old tag-stripping regex, quadratic on runs of '<' |
| P2-script-style-backtracking-regex | P2 | killed | 4.7 | script/style blocks removed with the old .*?</\1> regex instead of the forward scan |
| P8-extract-prompt-drops-data-boundary | P8 | killed | 4.1 | EXTRACT_SYSTEM no longer tells the model the paper is data, not instructions |
| P8-builder-takes-raw-paper-text | P8 | killed | 0.9 | the tool-holding Builder grows a raw-text channel for the paper |
