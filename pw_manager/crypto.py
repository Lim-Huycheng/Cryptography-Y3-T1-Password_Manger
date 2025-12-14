import secrets
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

class CryptoUtils:
    SALT_LEN = 16
    NONCE_LEN = 12
    KEY_LEN = 32

    @staticmethod
    def generate_salt() -> bytes:
        return secrets.token_bytes(CryptoUtils.SALT_LEN)

    @staticmethod
    def argon2id_kdf(password: str, salt: bytes) -> bytes:
        return hash_secret_raw(
            password.encode(),
            salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=1,
            hash_len=CryptoUtils.KEY_LEN,
            type=Type.ID
        )

    @staticmethod
    def hmac_derive(root_key: bytes, context: bytes) -> bytes:
        return hmac.new(root_key, context, hashlib.sha256).digest()

    @staticmethod
    def encrypt(key: bytes, plaintext: str) -> dict:
        aes = AESGCM(key)
        nonce = secrets.token_bytes(CryptoUtils.NONCE_LEN)
        ct = aes.encrypt(nonce, plaintext.encode(), b"vault")
        return {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode()
        }

    @staticmethod
    def decrypt(key: bytes, data: dict) -> str:
        aes = AESGCM(key)
        nonce = base64.b64decode(data["nonce"])
        ct = base64.b64decode(data["ciphertext"])
        return aes.decrypt(nonce, ct, b"vault").decode()
