def _presented(request):
    auth = request["headers"].get("Authorization", "")
    return auth[7:].strip() if auth.startswith("Bearer ") else ""


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
    key = "ip:" + request.get("remote_addr", "unknown")
    counts[key] = counts.get(key, 0) + 1
    if counts[key] > state["limit"]:
        return 429, headers
    if _presented(request) != state["api_key"]:          # short-circuits on the first wrong byte
        return 401, {**headers, "WWW-Authenticate": "Bearer"}
    return 200, headers
