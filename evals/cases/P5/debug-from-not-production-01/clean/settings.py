import os

from secprim import is_dev, require_secret


class Settings:
    def __init__(self, env=os.environ):
        self.debug = is_dev(env)                              # explicit dev labels only
        self.secret_key = require_secret("SECRET_KEY", dev_default="dev-secret-key", env=env)


settings = Settings()
