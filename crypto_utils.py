import base64
import json
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from argon2.low_level import hash_secret_raw, Type

KDF_PARAMS = {
    "time_cost": 3,
    "memory_cost": 64 * 1024,
    "parallelism": 2,
    "hash_len": 32
}

MAX_PASSWORD_LENGTH = 64
def derive_keys(password: str, salt: bytes):
    master_key = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=KDF_PARAMS["time_cost"],
        memory_cost=KDF_PARAMS["memory_cost"],
        parallelism=KDF_PARAMS["parallelism"],
        hash_len=KDF_PARAMS["hash_len"],
        type=Type.ID
    )

    hmac_key = HMAC.new(master_key, b"hmac_key", SHA256).digest()
    enc_key = HMAC.new(master_key, b"enc_key", SHA256).digest()

    return bytearray(hmac_key), bytearray(enc_key)


def encrypt_data(enc_key: bytearray, data: dict):
    nonce = get_random_bytes(12)
    cipher = AES.new(bytes(enc_key), AES.MODE_GCM, nonce=nonce)

    plaintext = json.dumps(data).encode("utf-8")
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }


def decrypt_data(enc_key: bytearray, enc_obj: dict):
    cipher = AES.new(
        bytes(enc_key),
        AES.MODE_GCM,
        nonce=base64.b64decode(enc_obj["nonce"])
    )

    decrypted = cipher.decrypt_and_verify(
        base64.b64decode(enc_obj["ciphertext"]),
        base64.b64decode(enc_obj["tag"])
    )
    return json.loads(decrypted.decode("utf-8"))

def pad(text: str) -> str:
    return text.ljust(MAX_PASSWORD_LENGTH, "\0")

def unpad(text: str) -> str:
    return text.rstrip("\0")
