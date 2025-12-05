import base64
import gc
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from crypto_utils import derive_keys, encrypt_data, decrypt_data, pad, unpad
from storage import load_vault_file, save_vault_file 
from utils import wipe_bytearray, wipe_str_dict
import gc
class SecureKeychain:
    def __init__(self, vault_path="vault.json"):
        self.vault_path = vault_path
        self.enc_key = None
        self.hmac_key = None
        self.salt = None
        self.data = {} 
        self.is_initialized = False 
        
    # Vault Initialization
    # --------------------------

    def create_vault(self, password: str):
        if load_vault_file(self.vault_path):
            print("Vault already exists.")
            return False

        self.salt = get_random_bytes(16)
        self.hmac_key, self.enc_key = derive_keys(password, self.salt)

        hmac_hash = HMAC.new(
            bytes(self.hmac_key),
            bytes(self.hmac_key),
            SHA256
        ).digest()

        save_vault_file(self.vault_path, self.salt, hmac_hash, {})
        self.is_initialized = True
        print("Vault created.")
        return True

    def load_vault(self, password: str):
        vault = load_vault_file(self.vault_path)
        if not vault:
            print("Vault not found.")
            wipe_bytearray(self.hmac_key)
            wipe_bytearray(self.enc_key)
            self.hmac_key = None
            self.enc_key = None
            self.salt = None
            return False

        self.salt = base64.b64decode(vault["salt"])
        self.hmac_key, self.enc_key = derive_keys(password, self.salt)

        stored_hmac_hash = base64.b64decode(vault["hmac_key_hash"])
        computed_hmac_hash = HMAC.new(
            bytes(self.hmac_key),
            bytes(self.hmac_key),
            SHA256
        ).digest()

        if stored_hmac_hash != computed_hmac_hash:
            print("Failed to load vault: Incorrect password.")
            wipe_bytearray(self.hmac_key)
            wipe_bytearray(self.enc_key)
            self.hmac_key = None
            self.enc_key = None
            self.salt = None
            return True 

        encrypted_data = vault.get("encrypted_data")
        try:
            if encrypted_data:
                self.data = decrypt_data(self.enc_key, encrypted_data)
            else:
                self.data = {}
        except (ValueError, KeyError) as e:
            print("Failed to load vault: Incorrect password or corrupted vault.")
            return False
        self.is_initialized = False
        print("Vault loaded.")
        return False
    
    # Save vault
    # --------------------------

    def _save(self):
        encrypted = encrypt_data(self.enc_key, self.data)
        hmac_hash = HMAC.new(bytes(self.hmac_key), bytes(self.hmac_key), SHA256).digest()
        save_vault_file(self.vault_path, self.salt, hmac_hash, encrypted)

    # Credential operations
    # --------------------------

    def add_credentials(self, domain, email, password):
        self.data[domain] = {
            "email": pad(email),
            "password": pad(password)
        }
        self._save()
        return True

    def get_credentials(self, domain):
        if domain not in self.data:
            return None
        entry = self.data[domain]
        return {
            "email": unpad(entry["email"]),
            "password": unpad(entry["password"]),
            "domain": domain
        }

    def delete_credentials(self, domain):
        if domain not in self.data:
            return False
        del self.data[domain]
        self._save()
        return True

    def list_domains(self):
        return list(self.data.keys())

    def get_domain_count(self):
        return len(self.data)

    # Vault Locking
    # --------------------------
    def lock_vault(self):
        # Wipe users stored credentials 
        if isinstance(self.data, dict):
            try:
                wipe_str_dict(self.data)
            except Exception:
                pass
        self.data = {}

        # Wipe cryptographic keys 
        for key_attr in ("hmac_key", "enc_key"):
            key_obj = getattr(self, key_attr, None)
            if isinstance(key_obj, (bytearray, bytes)):
                try:
                    wipe_bytearray(key_obj)
                except Exception:
                    pass
            if hasattr(self, key_attr):
                try:
                    delattr(self, key_attr)
                except Exception:
                    pass
        self.hmac_key = None
        self.enc_key = None
        self.is_initialized = False
        try:
            gc.collect()
        except Exception:
            pass
        print("Vault locked securely.")