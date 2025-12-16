import secrets
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

class CryptoUtils:
    SALT_LEN = 16                  # Salt length in bytes
    AES256_KEY_LEN = 32             # AES-256 key length in bytes
    AESGCM_NONCE_LEN = 12           # AES-GCM nonce length in bytes
    AAD = b"vault:v1"               # Associated data for AES-GCM

    @staticmethod
    def generate_salt() -> bytes:
        """Generate a random salt."""
        return secrets.token_bytes(CryptoUtils.SALT_LEN)

    @staticmethod
    def argon2id_kdf(password: str, salt: bytes) -> bytes:
        """
        Derive a fixed-length key from the master password using Argon2id.
        """
        return hash_secret_raw(
            secret=password.encode(),   # Must use 'secret', not 'password'
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=1,
            hash_len=CryptoUtils.AES256_KEY_LEN,
            type=Type.ID
        )

    @staticmethod
    def hmac_derive(root_key: bytes, context: bytes) -> bytes:
        """Derive a key using HMAC-SHA256 from a root key and context."""
        return hmac.new(root_key, context, hashlib.sha256).digest()

    @staticmethod
    def encrypt(key: bytes, plaintext: str) -> dict:
        """Encrypt plaintext using AES-256-GCM."""
        if len(key) != CryptoUtils.AES256_KEY_LEN:
            raise ValueError("Key must be 32 bytes (AES-256-GCM)")
        aes = AESGCM(key)
        nonce = secrets.token_bytes(CryptoUtils.AESGCM_NONCE_LEN)
        ciphertext = aes.encrypt(
            nonce=nonce,
            data=plaintext.encode(),
            associated_data=CryptoUtils.AAD
        )
        return {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

    @staticmethod
    def decrypt(key: bytes, data: dict) -> str:
        """Decrypt AES-256-GCM encrypted data."""
        if len(key) != CryptoUtils.AES256_KEY_LEN:
            raise ValueError("Key must be 32 bytes (AES-256-GCM)")
        aes = AESGCM(key)
        nonce = base64.b64decode(data["nonce"])
        ciphertext = base64.b64decode(data["ciphertext"])
        plaintext = aes.decrypt(
            nonce=nonce,
            data=ciphertext,
            associated_data=CryptoUtils.AAD
        )
        return plaintext.decode()
