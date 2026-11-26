from secprim import require_secret

# A default only when APP_ENV is unset or an explicit dev/test label; staging, qa,
# a typo or anything unrecognised raises MissingSecret at import time.
API_KEY = require_secret("API_KEY", dev_default="dev-placeholder-key")
