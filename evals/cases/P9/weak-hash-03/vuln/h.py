import hashlib
def token(secret: bytes) -> str:
    return hashlib.new("md5", secret).hexdigest()
