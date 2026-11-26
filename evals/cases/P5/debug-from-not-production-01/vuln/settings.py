import os


class Settings:
    def __init__(self, env=os.environ):
        self.app_env = env.get("APP_ENV", "dev").lower()
        self.debug = self.app_env != "production"            # staging -> True
        self.secret_key = env.get("SECRET_KEY") or ("dev-secret-key" if self.debug else None)
        if self.secret_key is None:
            raise RuntimeError("SECRET_KEY is required when DEBUG is off")


settings = Settings()
