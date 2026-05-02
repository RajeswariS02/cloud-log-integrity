import hashlib
import hmac
import os

# Secret key used to sign all log hashes.
# In production this would come from an environment variable.
# For the course demo, a hardcoded key is fine — just don't change it
# after logs are already stored or all existing hashes will break.
HMAC_SECRET = os.environ.get("LOG_HMAC_SECRET", "cloud-log-integrity-secret-key-2025")

def generate_hash(data: str) -> str:
    """
    Generate an HMAC-SHA256 digest of the given data string.
    Uses a secret key so that an attacker cannot recompute a valid
    hash after tampering — they would need the key too.
    """
    return hmac.new(
        HMAC_SECRET.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()

def generate_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()
