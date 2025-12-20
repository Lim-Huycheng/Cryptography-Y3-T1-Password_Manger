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
    
    # ==================== Vault Initialization ==================== #
    def initialize(self, master_password: str):
        if self.config_file.exists():
            UI.err("Vault already exists")
            return
        
        master_password = master_password.strip()
        if not master_password:
            UI.err("Master password cannot be empty")
            return
        salt = secrets.token_bytes(CryptoUtils.SALT_LEN)
        root_key = CryptoUtils.argon2id_kdf(master_password, salt)
        # Compute authentication hash using root_key
        # HMAC-SHA256: key=root_key, message="auth"
        auth_hash = hmac.new(root_key, b"auth", hashlib.sha256).digest()
        # Expand root key using HKDF for encryption
        stretched_key = CryptoUtils.hkdf_expand(root_key)
        # Save configuration
        self.config_file.write_text(json.dumps({
            "salt": base64.b64encode(salt).decode(),
            "auth": base64.b64encode(auth_hash).decode(),
            "created": datetime.now().isoformat(),
            "version": 1
        }, indent=2))
        # Initialize empty vault
        encrypted = CryptoUtils.encrypt(stretched_key, "{}")
        self.vault_file.write_text(json.dumps(encrypted, indent=2))
        UI.ok("Vault initialized")
    # ==================== Vault Unlock/Lock ==================== #
    def unlock(self, master_password: str):
        if not self.config_file.exists():
            UI.err("Vault not initialized")
            return
        
        master_password = master_password.strip()
        if not master_password:
            UI.err("Master password cannot be empty")
            return
        
        cfg = json.loads(self.config_file.read_text())
        salt = base64.b64decode(cfg["salt"])
        expected_auth = base64.b64decode(cfg["auth"])
        
        root_key = CryptoUtils.argon2id_kdf(master_password, salt)
        
        # Verify authentication hash
        computed_auth = hmac.new(root_key, b"auth", hashlib.sha256).digest()
        if not hmac.compare_digest(computed_auth, expected_auth):
            UI.err("Invalid password")
            return
        
        # Expand key for decryption
        stretched_key = CryptoUtils.hkdf_expand(root_key)
        encrypted_blob = json.loads(self.vault_file.read_text())
        
        try:
            self._entries = json.loads(CryptoUtils.decrypt(stretched_key, encrypted_blob))
        except Exception as e:
            UI.err(f"Failed to decrypt vault: {e}")
            return
        
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
    
    # ==================== Entry Operations ==================== #
    def _find_exact(self, service: str):
        """Find ALL entries by service name (case-insensitive)."""
        service = service.strip().lower()
        matches = [(eid, e) for eid, e in self._entries.items()
                   if e["service"].strip().lower() == service]
        return matches  # Return list of all matches
    
    def _find_exact_entry(self, service: str, username: str = None):
        """Find single entry by service name and optionally username."""
        service = service.strip().lower()
        matches = [(eid, e) for eid, e in self._entries.items()
                   if e["service"].strip().lower() == service]
        
        if username is None:
            # Return first match if only looking for service
            return matches[0] if len(matches) == 1 else None
        
        # Search for service + username combo
        username = username.strip().lower()
        exact_match = [(eid, e) for eid, e in matches
                       if e["username"].strip().lower() == username]
        return exact_match[0] if exact_match else None

    def add(self, service: str, username: str, password: str):
        """Add new entry (allows multiple accounts per service)"""
        if not self.is_unlocked:
            UI.err("Vault locked")
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
        
        # Check if this exact service + username combination exists
        if self._find_exact_entry(service, username):
            UI.err(f"Service '{service}' with username '{username}' already exists")
            return
        
        # Create new entry with unique ID
        entry_id = secrets.token_hex(16)
        self._entries[entry_id] = {
            "service": service,
            "username": username,
            "password": password,
            "created": datetime.now().isoformat()
        }
        self._save()
        UI.ok("Added")
    
    def list(self):
        """List all entries organized by service"""
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
            service = e["service"][:20].ljust(20)
            username = e["username"][:20].ljust(20)
            print(f"| {service} | {username} |")
        print("+----------------------+----------------------+\n")

    def get(self, service: str):
        """Get password - handles multiple accounts per service"""
        if not self.is_unlocked:
            UI.err("Vault locked")
            return
        
        service_lower = service.strip().lower()
        matches = [(eid, e) for eid, e in self._entries.items()
                   if e["service"].strip().lower() == service_lower]
        
        if not matches:
            UI.err("Not found")
            return
        
        # If multiple matches, ask user to choose
        if len(matches) > 1:
            print(f"\nFound {len(matches)} accounts for '{service}':")
            for i, (_, entry) in enumerate(matches, 1):
                print(f"{i}. {entry['username']}")
            
            while True:
                try:
                    choice = input("Select account (number): ").strip()
                    idx = int(choice) - 1
                    if 0 <= idx < len(matches):
                        break
                    UI.err(f"Please enter 1-{len(matches)}")
                except ValueError:
                    UI.err("Invalid input")
            
            _, entry = matches[idx]
        else:
            _, entry = matches[0]
        
        password = entry["password"]
        if not password:
            UI.err("Password is empty")
            return
        
        ClipboardManager.copy_and_clear(password)
        UI.ok(f"✓ Password for '{entry['service']}' ({entry['username']}) copied to clipboard")
    
    def update(self, service: str, username: str | None = None, password: str | None = None):
        """Update entry - handles multiple accounts per service"""
        if not self.is_unlocked:
            UI.err("Vault locked")
            return
        
        service_lower = service.strip().lower()
        matches = [(eid, e) for eid, e in self._entries.items()
                   if e["service"].strip().lower() == service_lower]
        
        if not matches:
            UI.err("Not found")
            return
        
        # If multiple matches, ask user to choose
        if len(matches) > 1:
            print(f"\nFound {len(matches)} accounts for '{service}':")
            for i, (_, entry) in enumerate(matches, 1):
                print(f"{i}. {entry['username']}")
            
            while True:
                try:
                    choice = input("Select account (number): ").strip()
                    idx = int(choice) - 1
                    if 0 <= idx < len(matches):
                        break
                    UI.err(f"Please enter 1-{len(matches)}")
                except ValueError:
                    UI.err("Invalid input")
            
            eid, entry = matches[idx]
        else:
            eid, entry = matches[0]
        
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
        """Delete entry - handles multiple accounts per service"""
        if not self.is_unlocked:
            UI.err("Vault locked")
            return
        
        service_lower = service.strip().lower()
        matches = [(eid, e) for eid, e in self._entries.items()
                   if e["service"].strip().lower() == service_lower]
        
        if not matches:
            UI.err("Not found")
            return
        
        # If multiple matches, ask user to choose
        if len(matches) > 1:
            print(f"\nFound {len(matches)} accounts for '{service}':")
            for i, (_, entry) in enumerate(matches, 1):
                print(f"{i}. {entry['username']}")
            
            while True:
                try:
                    choice = input("Select account (number): ").strip()
                    idx = int(choice) - 1
                    if 0 <= idx < len(matches):
                        break
                    UI.err(f"Please enter 1-{len(matches)}")
                except ValueError:
                    UI.err("Invalid input")
            
            eid, entry = matches[idx]
        else:
            eid, entry = matches[0]
        
        confirm = input(f"Delete '{entry['service']}' ({entry['username']})? (y/n): ").strip().lower()
        if confirm == "y":
            del self._entries[eid]
            self._save()
            UI.ok("Deleted")
        else:
            UI.info("Cancelled")