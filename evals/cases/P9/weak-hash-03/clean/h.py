import hashlib
def token(secret: bytes) -> str:
    return hashlib.new("sha256", secret).hexdigest()
