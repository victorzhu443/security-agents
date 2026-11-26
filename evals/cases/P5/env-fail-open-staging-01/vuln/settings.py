import os

APP_ENV = os.environ.get("APP_ENV", "dev")


def secret(name, dev_default):
    value = os.environ.get(name)
    if value:
        return value
    if APP_ENV in ("prod", "production"):          # everything else is "dev"
        raise RuntimeError(f"{name} is required in production")
    return dev_default


API_KEY = secret("API_KEY", "dev-placeholder-key")
