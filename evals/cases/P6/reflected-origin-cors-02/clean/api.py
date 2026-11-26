import hmac


class Api:
    def _presented(self, request):
        auth = request["headers"].get("Authorization", "")
        return auth[7:].strip() if auth.startswith("Bearer ") else ""

    def _token_ok(self, presented, state):
        return bool(presented) and hmac.compare_digest(
            presented.encode("utf-8"), state["api_key"].encode("utf-8"))

    def _cors(self, request, state):
        origin = request["headers"].get("Origin")
        if origin and origin in state["allowed_origins"]:
            return {"Access-Control-Allow-Origin": origin, "Vary": "Origin",
                    "Access-Control-Allow-Credentials": "true"}
        return {}

    def __call__(self, request, state):
        headers = self._cors(request, state)
        if request["method"] == "OPTIONS":
            return 204, headers
        counts = state.setdefault("counts", {})
        key = "ip:" + request.get("remote_addr", "unknown")
        counts[key] = counts.get(key, 0) + 1
        if counts[key] > state["limit"]:
            return 429, headers
        if not self._token_ok(self._presented(request), state):
            return 401, {**headers, "WWW-Authenticate": "Bearer"}
        return 200, headers


handle = Api()
