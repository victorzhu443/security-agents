"""Gate + limiter + CORS as one pure handler.

Order matters: the limiter counts every request to a limited route in the
before-request pass, so rejected requests consume the budget too.
"""
import hmac


def _presented(request):
    auth = request["headers"].get("Authorization", "")
    return auth[7:].strip() if auth.startswith("Bearer ") else ""


def _token_ok(presented, state):
    return bool(presented) and hmac.compare_digest(
        presented.encode("utf-8"), state["api_key"].encode("utf-8"))


def _limit_key(request, state):
    presented = _presented(request)
    if _token_ok(presented, state):
        return "token:" + presented
    return "ip:" + request.get("remote_addr", "unknown")   # bad tokens share the address bucket


def _cors(request, state):
    origin = request["headers"].get("Origin")
    if origin and origin in state["allowed_origins"]:
        return {"Access-Control-Allow-Origin": origin, "Vary": "Origin"}
    return {}


def handle(request, state):
    headers = _cors(request, state)
    if request["method"] == "OPTIONS":
        return 204, headers
    counts = state.setdefault("counts", {})
    key = _limit_key(request, state)
    counts[key] = counts.get(key, 0) + 1
    if counts[key] > state["limit"]:
        return 429, headers
    if not _token_ok(_presented(request), state):
        return 401, {**headers, "WWW-Authenticate": "Bearer"}
    return 200, headers
