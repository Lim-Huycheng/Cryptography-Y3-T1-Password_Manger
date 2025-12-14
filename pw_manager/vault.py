import json
import base64
import secrets
import hmac
from pathlib import Path
from datetime import datetime
from .crypto import CryptoUtils
from .clipboard import ClipboardManager

class PasswordVault:
    def __init__(self, vault_dir="save"):
        self.dir = Path(vault_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.vault_file = self.dir / "vault.json"
        self.config_file = self.dir / "config.json"
        self.key = None
        self.passwords = {}
        self.is_unlocked = False

    # ---------- INIT ----------
    def initialize(self, password: str):
        if self.config_file.exists():
            print("❌ Vault already exists")
            return

        salt = CryptoUtils.generate_salt()
        root = CryptoUtils.argon2id_kdf(password, salt)

        vault_key = CryptoUtils.hmac_derive(root, b"vault-key")
        verify_key = CryptoUtils.hmac_derive(root, b"verify-key")
        verify = CryptoUtils.hmac_derive(verify_key, b"check")

        self.config_file.write_text(json.dumps({
            "salt": base64.b64encode(salt).decode(),
            "verify": base64.b64encode(verify).decode(),
            "created": datetime.now().isoformat()
        }, indent=2))

        self.vault_file.write_text(json.dumps(
            CryptoUtils.encrypt(vault_key, "{}"), indent=2
        ))

        print("✓ Vault initialized")

    # ---------- UNLOCK ----------
    def unlock(self, password: str):
        if not self.config_file.exists():
            print("❌ Vault not initialized")
            return

        cfg = json.loads(self.config_file.read_text())
        salt = base64.b64decode(cfg["salt"])

        root = CryptoUtils.argon2id_kdf(password, salt)
        vault_key = CryptoUtils.hmac_derive(root, b"vault-key")
        verify_key = CryptoUtils.hmac_derive(root, b"verify-key")
        verify = CryptoUtils.hmac_derive(verify_key, b"check")

        if not hmac.compare_digest(
            verify,
            base64.b64decode(cfg["verify"])
        ):
            print("❌ Invalid password")
            return

        data = json.loads(self.vault_file.read_text())
        self.passwords = json.loads(CryptoUtils.decrypt(vault_key, data))
        self.key = vault_key
        self.is_unlocked = True
        print("✓ Vault unlocked")

    # ---------- LOCK ----------
    def lock(self):
        self.key = None
        self.passwords.clear()
        self.is_unlocked = False
        print("✓ Vault locked")

    # ---------- SAVE ----------
    def _save(self):
        self.vault_file.write_text(json.dumps(
            CryptoUtils.encrypt(self.key, json.dumps(self.passwords)), indent=2
        ))

    # ---------- CRUD ----------
    def add(self, service, username, password):
        if not self.is_unlocked:
            print("❌ Vault locked")
            return

        eid = secrets.token_hex(16)
        self.passwords[eid] = {
            "service": service,
            "username": username,
            "password": password,
            "created": datetime.now().isoformat()
        }
        self._save()
        print("✓ Added")

    def list(self):
        if not self.is_unlocked:
            print("❌ Vault locked")
            return

        if not self.passwords:
            print("📭 No entries")
            return

        print("\n+----------------------+----------------------+")
        print("| Service              | Username             |")
        print("+----------------------+----------------------+")
        for e in sorted(self.passwords.values(), key=lambda x: x["service"].lower()):
            print(f"| {e['service'][:20]:<20} | {e['username'][:20]:<20} |")
        print("+----------------------+----------------------+\n")

    def get(self, service):
        if not self.is_unlocked:
            print("❌ Vault locked")
            return

        matches = [e for e in self.passwords.values()
                   if service.lower() in e["service"].lower()]
        if len(matches) != 1:
            print("❌ Not found or ambiguous")
            return

        e = matches[0]
        ClipboardManager.copy_and_clear(e["password"])

    def update(self, service, username=None, password=None):
        if not self.is_unlocked:
            print("❌ Vault locked")
            return

        matches = [
            (k, v) for k, v in self.passwords.items()
            if service.lower() in v["service"].lower()
        ]

        if len(matches) != 1:
            print("❌ Not found or ambiguous")
            return

        key, entry = matches[0]

        if username is not None:
            entry["username"] = username
        if password is not None:
            entry["password"] = password

        entry["modified"] = datetime.now().isoformat()
        self._save()
        print("✓ Updated")

    def delete(self, service):
        if not self.is_unlocked:
            print("❌ Vault locked")
            return

        for k, v in list(self.passwords.items()):
            if service.lower() in v["service"].lower():
                del self.passwords[k]
                self._save()
                print("✓ Deleted")
                return
        print("❌ Not found")
