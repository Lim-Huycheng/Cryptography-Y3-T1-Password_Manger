import json
import base64
import secrets
import hmac
import string
from pathlib import Path
from datetime import datetime
from .crypto import CryptoUtils
from .clipboard import ClipboardManager

class PasswordVault:
    VAULT_FILENAME = "vault.json"
    CONFIG_FILENAME = "config.json"
    VAULT_KEY_CTX = b"vault-key"
    VERIFY_KEY_CTX = b"verify-key"
    VERIFY_CHECK_CTX = b"check"

    def __init__(self, vault_dir: str = "save"):
        self.dir = Path(vault_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

        self.vault_file = self.dir / self.VAULT_FILENAME
        self.config_file = self.dir / self.CONFIG_FILENAME

        self._vault_key: bytes | None = None
        self._entries: dict[str, dict] = {}
        self.is_unlocked: bool = False

    @staticmethod
    def generate_password(length: int = 16) -> str:
        charset = string.ascii_letters + string.digits + string.punctuation
        return "".join(secrets.choice(charset) for _ in range(length))

    def initialize(self, master_password: str) -> None:
        if self.config_file.exists():
            print("Vault already exists")
            return
        salt = CryptoUtils.generate_salt()
        root_key = CryptoUtils.argon2id_kdf(master_password, salt)

        vault_key = CryptoUtils.hmac_derive(root_key, self.VAULT_KEY_CTX)
        verify_key = CryptoUtils.hmac_derive(root_key, self.VERIFY_KEY_CTX)
        verify_token = CryptoUtils.hmac_derive(verify_key, self.VERIFY_CHECK_CTX)

        self.config_file.write_text(json.dumps({
            "salt": base64.b64encode(salt).decode(),
            "verify": base64.b64encode(verify_token).decode(),
            "created": datetime.now().isoformat(),
            "version": 1
        }, indent=2))

        self.vault_file.write_text(json.dumps(
            CryptoUtils.encrypt(vault_key, "{}"),
            indent=2
        ))

        print("✓ Vault initialized")
    def unlock(self, master_password: str) -> None:
        if not self.config_file.exists():
            print("Vault not initialized")
            return
        cfg = json.loads(self.config_file.read_text())
        salt = base64.b64decode(cfg["salt"])

        root_key = CryptoUtils.argon2id_kdf(master_password, salt)
        vault_key = CryptoUtils.hmac_derive(root_key, self.VAULT_KEY_CTX)
        verify_key = CryptoUtils.hmac_derive(root_key, self.VERIFY_KEY_CTX)
        verify_token = CryptoUtils.hmac_derive(verify_key, self.VERIFY_CHECK_CTX)

        if not hmac.compare_digest(
            verify_token,
            base64.b64decode(cfg["verify"])
        ):
            print("Invalid password")
            return
        encrypted_blob = json.loads(self.vault_file.read_text())
        self._entries = json.loads(CryptoUtils.decrypt(vault_key, encrypted_blob))
        self._vault_key = vault_key
        self.is_unlocked = True

        print("✓ Vault unlocked")

    def lock(self) -> None:
        self._vault_key = None
        self._entries.clear()
        self.is_unlocked = False
    def _save(self) -> None:
        if not self.is_unlocked or not self._vault_key:
            raise RuntimeError("Vault must be unlocked to save")

        encrypted = CryptoUtils.encrypt(
            self._vault_key,
            json.dumps(self._entries)
        )

        self.vault_file.write_text(json.dumps(encrypted, indent=2))

    def _find_exact(self, service: str):
        matches = [
            (eid, e) for eid, e in self._entries.items()
            if e["service"].lower() == service.lower()
        ]
        return matches[0] if len(matches) == 1 else None

    def add(self, service: str, username: str, password: str) -> None:
        if not self.is_unlocked:
            print("Vault locked")
            return
        service = service.strip()
        username = username.strip()
        password = password.strip()
        if not service or not username or not password:
            print("Service, username, and password are required")
            return
        if self._find_exact(service):
            print(f"🚫 Service '{service}' already exists")
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
    def list(self) -> None:
        if not self.is_unlocked:
            print("Vault locked")
            return
        if not self._entries:
            print("📭 No entries")
            return
        print("\n+----------------------+----------------------+")
        print("| Service              | Username             |")
        print("+----------------------+----------------------+")
        for e in sorted(self._entries.values(), key=lambda x: x["service"].lower()):
            print(f"| {e['service'][:20]:<20} | {e['username'][:20]:<20} |")
        print("+----------------------+----------------------+\n")

    def get(self, service: str) -> None:
        if not self.is_unlocked:
            print("Vault locked")
            return

        match = self._find_exact(service)
        if not match:
            print("Not found or ambiguous")
            return
        _, entry = match
        ClipboardManager.copy_and_clear(entry["password"])
    def update(self, service: str, username: str | None = None, password: str | None = None) -> None:
        if not self.is_unlocked:
            print("Vault locked")
            return
        match = self._find_exact(service)
        if not match:
            print("Not found or ambiguous")
            return
        eid, entry = match
        if username is not None:
            entry["username"] = username.strip()
        if password is not None:
            password = password.strip()
            if not password:
                print("Password cannot be empty")
                return
            entry["password"] = password

        entry["modified"] = datetime.now().isoformat()
        self._entries[eid] = entry
        self._save()
        print("✓ Updated")
    def delete(self, service: str) -> None:
        if not self.is_unlocked:
            print("Vault locked")
            return
        match = self._find_exact(service)
        if not match:
            print("Not found")
            return
        eid, _ = match
        del self._entries[eid]
        self._save()
        print("✓ Deleted")














