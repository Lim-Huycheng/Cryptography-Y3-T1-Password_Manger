import hashlib
import hmac
import secrets
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

class CryptoEngine:
    SALT_LENGTH = 16
    NONCE_LENGTH = 12
    KEY_LENGTH = 32

    @staticmethod
    def generate_salt() -> bytes:
        return secrets.token_bytes(CryptoEngine.SALT_LENGTH)
    @staticmethod
    def argon2id_kdf(password: str, salt: bytes) -> bytes:
        return hash_secret_raw(
            password.encode(),
            salt,
            time_cost=2,
            memory_cost=19,
            parallelism=1,
            hash_len=CryptoEngine.KEY_LENGTH,  # 32 bytes = AES-256
            type=Type.ID
    )
    @staticmethod
    def separate_keys(master_key: bytes, fixed_salt: bytes = None) -> tuple:
        if fixed_salt is None:
            enc_salt = secrets.token_bytes(CryptoEngine.SALT_LENGTH)
            hmac_salt = secrets.token_bytes(CryptoEngine.SALT_LENGTH)
        else:
            enc_salt = hashlib.sha256(fixed_salt + b"enc").digest()[:CryptoEngine.SALT_LENGTH]
            hmac_salt = hashlib.sha256(fixed_salt + b"hmac").digest()[:CryptoEngine.SALT_LENGTH]

        enc_key = CryptoEngine.argon2id_kdf(
            master_key.hex() + ":encryption",
            enc_salt
        )

        hmac_key = CryptoEngine.argon2id_kdf(
            master_key.hex() + ":hmac",
            hmac_salt
        )
        return enc_key, hmac_key, enc_salt, hmac_salt

    @staticmethod
    def generate_hmac(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    @staticmethod
    def encrypt_aes256gcm(key: bytes, plaintext: str) -> dict:
        cipher = AESGCM(key)
        nonce = secrets.token_bytes(CryptoEngine.NONCE_LENGTH)
        ciphertext = cipher.encrypt(nonce, plaintext.encode(), b"password-vault")

        return {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

    @staticmethod
    def decrypt_aes256gcm(key: bytes, encrypted: dict) -> str:
        cipher = AESGCM(key)
        nonce = base64.b64decode(encrypted["nonce"])
        ciphertext = base64.b64decode(encrypted["ciphertext"])
        plaintext = cipher.decrypt(nonce, ciphertext, b"password-vault")
        return plaintext.decode()

    