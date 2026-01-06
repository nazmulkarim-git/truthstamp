import os

def env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}

PAYWALL_ENABLED = env_bool("TRUTHSTAMP_PAYWALL_ENABLED", False)
PRICE_USD = int(os.getenv("TRUTHSTAMP_PRICE_USD", "15"))
MAX_MB = int(os.getenv("TRUTHSTAMP_MAX_MB", "50"))
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
