import hashlib


def token_fingerprint(session_token: str) -> str:
    """Stored server-side and compared to authenticate later requests."""
    return hashlib.sha256(session_token.encode()).hexdigest()
