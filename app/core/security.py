import hashlib
import hmac
import secrets
import sys

from cryptography.fernet import Fernet, InvalidToken

from core.errors import SecurityError

def generate_api_key() -> str:
    return secrets.token_urlsafe(32)

def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode('utf-8')).hexdigest()

def verify_api_key(presented: str, allowed_hashes: tuple[str, ...]) -> bool:
    presented_hash = hash_api_key(presented)
    matched = False
    for allowed in allowed_hashes:
        matched |= hmac.compare_digest(presented_hash, allowed)
    return matched

def generate_encryption_key() -> str:
    return Fernet.generate_key().decode('ascii')

def encrypt_secret(plaintext: str, key: str) -> str:
    return Fernet(key).encrypt(plaintext.encode('utf-8')).decode('ascii')

def decrypt_secret(token: str, key: str) -> str:
    try:
        return Fernet(key).decrypt(token.encode('ascii')).decode('utf-8')
    except InvalidToken:
        raise SecurityError('stored secret cannot be decrypted with the configured key') from None

if __name__ == '__main__':
    if sys.argv[1:] == ['encryption-key']:
        print(f'Encryption key (set CRED_ENCRYPTION_KEY in .env; back it up, losing it makes stored passwords unreadable): {generate_encryption_key()}')
    else:
        key = generate_api_key()
        print(f'API key (give to the client, store nowhere else): {key}')
        print(f'Hash (append to API_KEY_HASHES in .env):          {hash_api_key(key)}')
