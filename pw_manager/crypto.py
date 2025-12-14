import secrets
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

class CryptoUtils:
    SALT_LENGTH = 16
    NONCE_LENGTH = 12
    KEY_LENGTH = 32  # 256-bit AES key

    @staticmethod
    def generate_salt() -> bytes:
        return secrets.token_bytes(CryptoUtils.SALT_LENGTH)

    @staticmethod
    def argon2id_kdf(password: str, salt: bytes) -> bytes:
        """
        Derive a strong key from a password using Argon2id.
        Adjusted for better security.
        """
        return hash_secret_raw(
            password.encode(),
            salt,
            time_cost=3,       # increase for slightly more CPU hardness
            memory_cost=65536, # 64 MiB memory cost
            parallelism=1,
            hash_len=CryptoUtils.KEY_LENGTH,
            type=Type.ID
        )

    @staticmethod
    def encrypt_aes256gcm(key: bytes, plaintext: str) -> dict:
        cipher = AESGCM(key)
        nonce = secrets.token_bytes(CryptoUtils.NONCE_LENGTH)
        ciphertext = cipher.encrypt(nonce, plaintext.encode(), b"vault")
        return {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

    @staticmethod
    def decrypt_aes256gcm(key: bytes, encrypted: dict) -> str:
        cipher = AESGCM(key)
        nonce = base64.b64decode(encrypted["nonce"])
        ciphertext = base64.b64decode(encrypted["ciphertext"])
        plaintext = cipher.decrypt(nonce, ciphertext, b"vault")
        return plaintext.decode()
