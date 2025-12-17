import secrets
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

class CryptoUtils:
    SALT_LEN = 16                  
    AES256_KEY_LEN = 32            
    AESGCM_NONCE_LEN = 12          
    AAD = b"vault:v1"              
    @staticmethod
    def generate_salt() -> bytes:
        return secrets.token_bytes(CryptoUtils.SALT_LEN)
    @staticmethod
    def argon2id_kdf(password: str, salt: bytes) -> bytes:
        return hash_secret_raw(
            secret=password.encode(),  
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=1,
            hash_len=CryptoUtils.AES256_KEY_LEN,
            type=Type.ID
        )
    @staticmethod
    def hmac_derive(root_key: bytes, context: bytes) -> bytes:
        return hmac.new(root_key, context, hashlib.sha256).digest()
    @staticmethod
    def encrypt(key: bytes, plaintext: str) -> dict:
        if len(key) != CryptoUtils.AES256_KEY_LEN:
            raise ValueError("Key must be 32 bytes")
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
        if len(key) != CryptoUtils.AES256_KEY_LEN:
            raise ValueError("Key must be 32 bytes")
        aes = AESGCM(key)
        nonce = base64.b64decode(data["nonce"])
        ciphertext = base64.b64decode(data["ciphertext"])
        plaintext = aes.decrypt(
            nonce=nonce,
            data=ciphertext,
            associated_data=CryptoUtils.AAD
        )
        return plaintext.decode()











