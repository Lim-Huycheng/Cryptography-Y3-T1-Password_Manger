import secrets
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from argon2.low_level import hash_secret_raw, Type
class CryptoUtils:
    SALT_LEN = 16
    AES256_KEY_LEN = 32  
    AESGCM_NONCE_LEN = 12
    AAD = b"vault:v1"
    
    @staticmethod
    def argon2id_kdf(password: str, salt: bytes, time_cost: int = 3, memory_cost: int = 65536) -> bytes:
        return hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=1,
            hash_len=32,  
            type=Type.ID
        )
    @staticmethod
    def hkdf_expand(key: bytes, info: bytes = b"vault-stretch", length: int = 64) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=info
        )
        return hkdf.derive(key)
    @staticmethod
    #AES-GCM: Key, Nonce, AAD
    def encrypt(key: bytes, plaintext: str) -> dict:
        if len(key) < CryptoUtils.AES256_KEY_LEN:
            raise ValueError("Key must be at least 32 bytes")
        aes = AESGCM(key[:32])
        nonce = secrets.token_bytes(CryptoUtils.AESGCM_NONCE_LEN)
        ciphertext = aes.encrypt(
            nonce=nonce,
            data=plaintext.encode(),
            associated_data=CryptoUtils.AAD
        )
        mac = hmac.new(key[32:], ciphertext, hashlib.sha256).digest()
        return {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "mac": base64.b64encode(mac).decode()
        }
    @staticmethod
    def decrypt(key: bytes, data: dict) -> str:
        if len(key) < CryptoUtils.AES256_KEY_LEN:
            raise ValueError("Key must be at least 32 bytes")
        nonce = base64.b64decode(data["nonce"])
        ciphertext = base64.b64decode(data["ciphertext"])
        mac = base64.b64decode(data["mac"])
        if not hmac.compare_digest(hmac.new(key[32:], ciphertext, hashlib.sha256).digest(), mac):
            raise ValueError("MAC verification failed. Data may be tampered.")
        aes = AESGCM(key[:32])
        plaintext = aes.decrypt(
            nonce=nonce,
            data=ciphertext,
            associated_data=CryptoUtils.AAD
        )
        return plaintext.decode()
