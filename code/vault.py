import json
import base64
import secrets
import hmac
import hashlib
from pathlib import Path
from datetime import datetime
from .crypto import CryptoUtils
from .clipboard import ClipboardManager
from .color import UI
class PasswordVault:
    VAULT_FILENAME = "vault.json"
    CONFIG_FILENAME = "config.json"
    def __init__(self, vault_dir: str = "save"):
        self.dir = Path(vault_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.vault_file = self.dir / self.VAULT_FILENAME
        self.config_file = self.dir / self.CONFIG_FILENAME
        self._master_key: bytes | None = None
        self._entries: dict[str, dict] = {}
        self.is_unlocked = False
    # ------------------ Vault Initialization ------------------ #
    def initialize(self, master_password: str, email: str):
        if self.config_file.exists():
            UI.err("Vault already exists")
            return
        email = email.strip().lower() 
        email_bytes = email.encode()
        salt = hashlib.sha256(email_bytes).digest()
        root_key = CryptoUtils.argon2id_kdf(master_password, salt)
        stretched_key = CryptoUtils.hkdf_expand(root_key)
        #HMAC: Key , Message
        auth_hash = hmac.new(salt, root_key, hashlib.sha256).digest()
        self.config_file.write_text(json.dumps({
            "email": email,
            "salt": base64.b64encode(salt).decode(),
            "auth": base64.b64encode(auth_hash).decode(),
            "created": datetime.now().isoformat(),
            "version": 1
        }, indent=2))
        # Initialize empty vault
        encrypted = CryptoUtils.encrypt(stretched_key, "{}")
        self.vault_file.write_text(json.dumps(encrypted, indent=2))
        UI.ok("✓ Vault initialized")
    # ------------------ Vault Unlock/Lock ------------------ #
    def unlock(self, master_password: str, email: str):
        if not self.config_file.exists():
            UI.err("Vault not initialized")
            return
        email = email.strip().lower()
        cfg = json.loads(self.config_file.read_text())
        cfg_email = cfg.get("email", "").strip().lower()
        if cfg_email != email:
            UI.err("Email does not match vault")
            return
        salt = base64.b64decode(cfg["salt"])
        expected_auth = base64.b64decode(cfg["auth"])

        root_key = CryptoUtils.argon2id_kdf(master_password, salt)
        if not hmac.compare_digest(hmac.new(salt, root_key, hashlib.sha256).digest(), expected_auth):
            UI.err("Invalid password")
            return
        stretched_key = CryptoUtils.hkdf_expand(root_key)
        encrypted_blob = json.loads(self.vault_file.read_text())
        self._entries = json.loads(CryptoUtils.decrypt(stretched_key, encrypted_blob))
        self._master_key = stretched_key
        self.is_unlocked = True
        UI.ok("Vault unlocked")
    def lock(self):
        self._master_key = None
        self._entries.clear()
        self.is_unlocked = False
    def _save(self):
        if not self.is_unlocked or not self._master_key:
            raise RuntimeError("Vault must be unlocked to save")
        encrypted = CryptoUtils.encrypt(self._master_key, json.dumps(self._entries))
        self.vault_file.write_text(json.dumps(encrypted, indent=2))
    # ------------------ Entry Operations ------------------ #
    def _find_exact(self, service: str):
        service = service.strip().lower()
        matches = [(eid, e) for eid, e in self._entries.items()
                   if e["service"].strip().lower() == service]
        return matches[0] if len(matches) == 1 else None
    def add(self, service: str, username: str, password: str):
        if not self.is_unlocked:
            UI.ok("Vault locked")
            return
        service = service.strip()
        username = username.strip()
        password = password.strip()
        if not service:
            UI.err("Service cannot be empty")
            return
        if not username:
            UI.err("Username cannot be empty")
            return
        if not password:
            UI.err("Password cannot be empty")
            return

        if self._find_exact(service):
            UI.err(f"Service '{service}' already exists")
            return
        entry_id = secrets.token_hex(16)
        self._entries[entry_id] = {
            "service": service,
            "username": username,
            "password": password,
            "created": datetime.now().isoformat()
        }
        self._save()
        print("✓ Added")
    def list(self):
        if not self.is_unlocked:
            UI.err("Vault locked")
            return
        if not self._entries:
            UI.info("📭 No entries")
            return
        print("\n+----------------------+----------------------+")
        print("| Service              | Username             |")
        print("+----------------------+----------------------+")
        for e in sorted(self._entries.values(), key=lambda x: x["service"].lower()):
            print(f"| {e['service'][:20]:<20} | {e['username'][:20]:<20} |")
        print("+----------------------+----------------------+\n")
    def get(self, service: str):
        if not self.is_unlocked:
            UI.err("Vault locked")
            return
        match = self._find_exact(service)
        if not match:
            UI.err("Not found...")
            return
        _, entry = match
        password = entry["password"].strip()
        if not password:
            UI.err("Password is empty, cannot copy")
            return
        ClipboardManager.copy_and_clear(password)
        UI.ok(f"Password for '{entry['service']}' copied to clipboard")

    def update(self, service: str, username: str | None = None, password: str | None = None):
        if not self.is_unlocked:
            UI.err("Vault locked")
            return
        match = self._find_exact(service)
        if not match:
            UI.err("Not found...")
            return
        eid, entry = match
        if username is not None:
            username = username.strip()
            if username:
                entry["username"] = username
        if password is not None:
            password = password.strip()
            if not password:
                UI.err("Password cannot be empty")
                return
            entry["password"] = password

        entry["modified"] = datetime.now().isoformat()
        self._entries[eid] = entry
        self._save()
        UI.ok("Updated")
    def delete(self, service: str):
        if not self.is_unlocked:
            UI.err("Vault locked")
            return
        match = self._find_exact(service)
        if not match:
            UI.err("Not found")
            return
        eid, _ = match
        del self._entries[eid]
        self._save()
        UI.ok("Deleted")



