"""Gate first, then the view with its own limiter: rejected requests are free."""
import hmac


def _presented(request):
    auth = request["headers"].get("Authorization", "")
    return auth[7:].strip() if auth.startswith("Bearer ") else ""


def _token_ok(presented, state):
    return bool(presented) and hmac.compare_digest(
        presented.encode("utf-8"), state["api_key"].encode("utf-8"))


def _cors(request, state):
    origin = request["headers"].get("Origin")
    if origin and origin in state["allowed_origins"]:
        return {"Access-Control-Allow-Origin": origin, "Vary": "Origin"}
    return {}


def _view(request, state, headers):
    counts = state.setdefault("counts", {})          # @limiter.limit on the view
    key = "token:" + _presented(request)
    counts[key] = counts.get(key, 0) + 1
    if counts[key] > state["limit"]:
        return 429, headers
    return 200, headers


def handle(request, state):
    headers = _cors(request, state)
    if request["method"] == "OPTIONS":
        return 204, headers
    if not _token_ok(_presented(request), state):    # before_request gate
        return 401, {**headers, "WWW-Authenticate": "Bearer"}
    return _view(request, state, headers)
