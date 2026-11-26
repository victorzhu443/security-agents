"""P6 access-control graders (plugin): probes against a pure handler.

The case exposes `handle(request: dict, state: dict) -> (status, headers)` with
no web framework (CI needs nothing new). The grader builds `state` from the
case's `expect` and owns it for the whole probe, so the handler keeps its
counters in it:

    request  {"method", "path", "headers": {...}, "remote_addr"}
    state    {"api_key", "limit", "allowed_origins", ...handler's own keys}

    access         expect: {target: "api:handle", token: "...", limit: N,
                            path: "/forecast", allowed_origin: "https://..."}
        Probes: no token -> 401; wrong token -> 401; N+1 rejected requests from
        one client -> the (N+1)th is 429 (a limiter on the success path only is
        the historical miss); N+1 accepted requests -> 429; a preflight and a
        response for an off-list Origin carry no `*` and do not echo the origin.
        Detected = any probe fails. If a valid token is not accepted at all the
        handler is broken, not clean: the grader errors.

    token_compare  same expect. Static: the handler module must not compare the
        presented credential with `==`/`!=` (timing side channel); the fix is
        `hmac.compare_digest`. Detected = an equality comparison whose operand
        names a token/key/secret. The no-token and wrong-token probes run as a
        sanity gate so that deleting the gate does not count as a fix.
"""
from __future__ import annotations

import ast
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from .graders import Case, Result, load_attr

EVIL_ORIGIN = "https://evil.test"
CLIENT = "203.0.113.5"
CREDENTIAL_WORDS = re.compile(r"token|key|secret|bearer|presented|credential|password", re.I)


def make_request(method="GET", path="/forecast", token: Optional[str] = None,
                 origin: Optional[str] = None, preflight=False, addr=CLIENT) -> Dict[str, Any]:
    headers: Dict[str, str] = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if origin:
        headers["Origin"] = origin
    if preflight:
        headers["Access-Control-Request-Method"] = "GET"
    return {"method": method, "path": path, "headers": headers, "remote_addr": addr}


def _call(fn, request, state) -> Tuple[int, Dict[str, str]]:
    status, headers = fn(request, state)
    return int(status), {str(k).lower(): str(v) for k, v in dict(headers or {}).items()}


def _acao(headers: Dict[str, str]) -> Optional[str]:
    return headers.get("access-control-allow-origin")


def _probe(fn: Callable, expect: Dict[str, Any]) -> Tuple[List[str], Dict[str, Any], Optional[str]]:
    """(breaches, metrics, error)."""
    token, limit = expect["token"], int(expect.get("limit", 5))
    path, allowed = expect.get("path", "/forecast"), expect.get("allowed_origin", "https://dashboard.test")

    def fresh():
        return {"api_key": token, "limit": limit, "allowed_origins": [allowed]}

    breaches: List[str] = []
    m: Dict[str, Any] = {}

    status, _ = _call(fn, make_request(path=path, token=token), fresh())
    m["valid_token"] = status
    if status != 200:
        return breaches, m, f"valid token got {status}, not 200 — handler cannot be judged"

    status, _ = _call(fn, make_request(path=path), fresh())
    m["no_token"] = status
    if status != 401:
        breaches.append(f"no token -> {status}, want 401")

    status, _ = _call(fn, make_request(path=path, token="not-the-" + token), fresh())
    m["wrong_token"] = status
    if status != 401:
        breaches.append(f"wrong token -> {status}, want 401")

    state = fresh()                                           # the historical miss
    seq = [_call(fn, make_request(path=path, token="wrong-" + token), state)[0]
           for _ in range(limit + 1)]
    m["rejected_sequence"] = seq
    if seq[-1] != 429:
        breaches.append(f"request {limit + 1} after {limit} rejected ones -> {seq[-1]}, want 429")

    state = fresh()
    seq = [_call(fn, make_request(path=path, token=token), state)[0] for _ in range(limit + 1)]
    m["accepted_sequence"] = seq
    if seq[-1] != 429:
        breaches.append(f"request {limit + 1} after {limit} accepted ones -> {seq[-1]}, want 429")

    _, headers = _call(fn, make_request("OPTIONS", path, origin=EVIL_ORIGIN, preflight=True), fresh())
    m["preflight_off_list_acao"] = _acao(headers)
    if _acao(headers) in ("*", EVIL_ORIGIN):
        breaches.append(f"preflight from {EVIL_ORIGIN} -> Access-Control-Allow-Origin: {_acao(headers)}")

    _, headers = _call(fn, make_request(path=path, token=token, origin=EVIL_ORIGIN), fresh())
    m["response_off_list_acao"] = _acao(headers)
    if _acao(headers) in ("*", EVIL_ORIGIN):
        breaches.append(f"response to {EVIL_ORIGIN} -> Access-Control-Allow-Origin: {_acao(headers)}")

    _, headers = _call(fn, make_request("OPTIONS", path, origin=allowed, preflight=True), fresh())
    m["preflight_allowed_acao"] = _acao(headers)          # recorded, not judged
    return breaches, m, None


class AccessGrader:
    name = "access"

    def grade(self, case: Case, variant: str) -> Result:
        try:
            fn = load_attr(case.variant_dir(variant), case.expect["target"])
        except Exception as e:  # noqa: BLE001
            return Result(False, error=f"load: {e!r}")
        try:
            breaches, metrics, error = _probe(fn, case.expect)
        except Exception as e:  # noqa: BLE001
            return Result(False, error=f"handler raised {e!r}")
        if error:
            return Result(False, metrics=metrics, error=error)
        return Result(detected=bool(breaches), metrics=metrics,
                      evidence="; ".join(breaches)[:400] or "every probe answered correctly")


def equality_on_credential(source: str) -> List[str]:
    """Lines where a credential-named operand is compared with == / !=."""
    tree = ast.parse(source)
    hits: List[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        if not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            continue
        for operand in [node.left, *node.comparators]:
            text = ast.get_source_segment(source, operand) or ""
            if CREDENTIAL_WORDS.search(text):
                hits.append(f"line {node.lineno}: {ast.get_source_segment(source, node)}")
                break
    return hits


class TokenCompareGrader:
    name = "token_compare"

    def grade(self, case: Case, variant: str) -> Result:
        mod_name = case.expect["target"].partition(":")[0]
        path = case.variant_dir(variant) / (mod_name.replace(".", "/") + ".py")
        try:
            fn = load_attr(case.variant_dir(variant), case.expect["target"])
            source = path.read_text()
        except Exception as e:  # noqa: BLE001
            return Result(False, error=f"load: {e!r}")
        # sanity: the gate must still exist and work
        try:
            breaches, metrics, error = _probe(fn, case.expect)
        except Exception as e:  # noqa: BLE001
            return Result(False, error=f"handler raised {e!r}")
        if error:
            return Result(False, metrics=metrics, error=error)
        gate = [b for b in breaches if b.startswith(("no token", "wrong token"))]
        if gate:
            return Result(False, metrics=metrics, error="gate missing: " + "; ".join(gate))
        hits = equality_on_credential(source)
        return Result(detected=bool(hits), metrics={"equality_compares": hits, **metrics},
                      evidence="; ".join(hits)[:400] or "no equality comparison on a credential")


GRADERS = {"access": AccessGrader(), "token_compare": TokenCompareGrader()}
