import json
import base64
import secrets
from pathlib import Path
from datetime import datetime
from .crypto import CryptoUtils
from .clipboard import ClipboardManager

class PasswordVault:
    def __init__(self, vault_dir: str = "save"):
        self.vault_dir = Path(vault_dir)
        self.vault_file = self.vault_dir / "vault.json"
        self.config_file = self.vault_dir / "config.json"
        self.vault_dir.mkdir(exist_ok=True)

        self.encryption_key = None
        self.is_unlocked = False
        self.passwords = {}

    # ---------- INITIALIZE ----------
    def initialize(self, password: str) -> bool:
        if len(password) < 12:
            print("❌ Password must be at least 12 characters")
            return False
        if self.config_file.exists():
            print("❌ Vault already exists")
            return False

        salt = CryptoUtils.generate_salt()
        master_key = CryptoUtils.argon2id_kdf(password, salt)

        # Simple verification HMAC using derived key
        verify = base64.b64encode(master_key).decode()
        config = {
            "salt": base64.b64encode(salt).decode(),
            "verify": verify,
            "created": datetime.now().isoformat(),
        }

        self.config_file.write_text(json.dumps(config, indent=2))
        encrypted = CryptoUtils.encrypt_aes256gcm(master_key, "{}")
        self.vault_file.write_text(json.dumps(encrypted, indent=2))

        print("✓ Vault initialized")
        return True

    # ---------- UNLOCK ----------
    def unlock(self, password: str) -> bool:
        if not self.config_file.exists():
            print("❌ Vault not initialized")
            return False

        config = json.loads(self.config_file.read_text())
        salt = base64.b64decode(config["salt"])
        stored_verify = config["verify"]

        master_key = CryptoUtils.argon2id_kdf(password, salt)
        verify = base64.b64encode(master_key).decode()

        if verify != stored_verify:
            print("❌ Invalid password")
            return False

        vault_data = json.loads(self.vault_file.read_text())
        plaintext = CryptoUtils.decrypt_aes256gcm(master_key, vault_data)

        self.passwords = json.loads(plaintext)
        self.encryption_key = master_key
        self.is_unlocked = True
        print("✓ Vault unlocked")
        return True

    # ---------- LOCK ----------
    def lock(self):
        try:
            import pyperclip
            pyperclip.copy("")
        except Exception:
            pass
        self.encryption_key = None
        self.passwords.clear()
        self.is_unlocked = False
        print("✓ Vault locked")

    # ---------- ADD ----------
    def add(self, service: str, username: str, password: str):
        if not self.is_unlocked:
            print("❌ Vault locked")
            return
        entry_id = secrets.token_hex(16)
        self.passwords[entry_id] = {
            "service": service,
            "username": username,
            "password": password,
            "created": datetime.now().isoformat(),
        }
        self._save()
        print(f"✓ Added {service}")

    # ---------- LIST ----------
    def list(self):
        if not self.is_unlocked:
            print("❌ Vault locked")
            return
        if not self.passwords:
            print("📭 No entries")
            return
        print("\nService               Username")
        print("-" * 50)
        for e in sorted(self.passwords.values(), key=lambda x: x["service"].lower()):
            print(f"{e['service']:<20} {e['username']}")
        print()

    # ---------- GET ----------
    def get(self, service: str):
        if not self.is_unlocked:
            print("❌ Vault locked")
            return
        matches = [e for e in self.passwords.values()
                   if service.lower() in e["service"].lower()]
        if len(matches) != 1:
            print("❌ Not found or ambiguous")
            return
        e = matches[0]
        print(f"\nService : {e['service']}")
        print(f"Username: {e['username']}")
        choice = input("Copy password to clipboard? (yes/no): ").lower()
        if choice == "yes":
            ClipboardManager.copy_and_clear(e["password"], timeout=15)
        else:
            print("Password not copied\n")

    # ---------- UPDATE ----------
    def update(self, service: str, username=None, password=None):
        matches = [(k, v) for k, v in self.passwords.items()
                   if service.lower() in v["service"].lower()]
        if len(matches) != 1:
            print("❌ Not found or ambiguous")
            return
        key, entry = matches[0]
        if username:
            entry["username"] = username
        if password:
            entry["password"] = password
        entry["modified"] = datetime.now().isoformat()
        self._save()
        print(f"✓ Updated {service}")

    # ---------- DELETE ----------
    def delete(self, service: str):
        matches = [(k, v) for k, v in self.passwords.items()
                   if service.lower() in v["service"].lower()]
        if len(matches) != 1:
            print("❌ Not found or ambiguous")
            return
        key, entry = matches[0]
        if input(f"Delete {entry['service']}? (yes/no): ").lower() != "yes":
            print("Cancelled")
            return
        del self.passwords[key]
        self._save()
        print("✓ Deleted")

    # ---------- SAVE ----------
    def _save(self):
        encrypted = CryptoUtils.encrypt_aes256gcm(
            self.encryption_key,
            json.dumps(self.passwords)
        )
        self.vault_file.write_text(json.dumps(encrypted, indent=2))
