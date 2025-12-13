import json
import hmac
import base64
from pathlib import Path
from datetime import datetime
from .crypto import CryptoEngine

class SecureVault:
    def __init__(self, vault_dir: str = None):
        if vault_dir is None:
            vault_dir = "D:/final_cryptography/SecureVault/vault"
        
        self.vault_dir = Path(vault_dir)
        self.vault_file = self.vault_dir / "vault.json"
        self.config_file = self.vault_dir / "config.json"
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        
        self.master_key = None
        self.encryption_key = None
        self.is_unlocked = False
        self.passwords = {}
    
    def initialize(self, password: str) -> bool:
        if len(password) < 12:
            print("❌ Password must be 12+ characters")
            return False
        
        if self.config_file.exists():
            print("❌ Vault already exists")
            return False
        
        try:
            print("⏳ Initializing... ")
            salt = CryptoEngine.generate_salt()
            master_key = CryptoEngine.argon2id_kdf(password, salt)
            # key_derived = password + salt 
            enc_key, hmac_key, enc_salt, hmac_salt = CryptoEngine.separate_keys(master_key, salt)
            verify_hash = CryptoEngine.generate_hmac(hmac_key, password.encode())
            config = {
                "salt": base64.b64encode(salt).decode(),
                "enc_salt": base64.b64encode(enc_salt).decode(),
                "hmac_salt": base64.b64encode(hmac_salt).decode(),
                "verification_hash": base64.b64encode(verify_hash).decode(),
                "created_at": datetime.now().isoformat()
            }
            
            self.config_file.write_text(json.dumps(config, indent=2))
            
            # Create empty encrypted vault, {} is for user's metadata entry encrypted
            empty_vault = CryptoEngine.encrypt_aes256gcm(enc_key, "{}")
            self.vault_file.write_text(json.dumps(empty_vault, indent=2))
            
            print("✓ Vault initialized")
            return True
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
    
    def unlock(self, password: str) -> bool:
        if not self.config_file.exists():
            print("❌ Vault not initialized. Run 'init'")
            return False
        
        try:
            print("⏳ Unlocking")
            
            # Load config and verify password
            config = json.loads(self.config_file.read_text())
            salt = base64.b64decode(config["salt"])
            stored_hash = base64.b64decode(config["verification_hash"])
            master_key = CryptoEngine.argon2id_kdf(password, salt)
            enc_key, hmac_key, _, _ = CryptoEngine.separate_keys(master_key, salt)
            verify_hash = CryptoEngine.generate_hmac(hmac_key, password.encode())
            
            if not hmac.compare_digest(verify_hash, stored_hash):
                print("❌ Invalid password")
                return False
            
            self.master_key = master_key
            self.encryption_key = enc_key
            self.is_unlocked = True
            
            vault_data = json.loads(self.vault_file.read_text())
            plaintext = CryptoEngine.decrypt_aes256gcm(enc_key, vault_data)
            self.passwords = json.loads(plaintext)
            
            print("✓ Vault unlocked")
            return True
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
    
    def lock(self):
        self.encryption_key = None
        self.is_unlocked = False
        self.passwords = {}
        print("✓ Vault locked")
    
    def add(self, service: str, username: str, password: str) -> bool:
        if not self.is_unlocked:
            print("❌ Vault locked")
            return False
        
        if not all([service, username, password]):
            print("❌ All fields required")
            return False
        
        try:
            entry_id = f"{service.lower()}_{datetime.now().timestamp()}"
            self.passwords[entry_id] = {
                "service": service,
                "username": username,
                "password": password,
                "added_at": datetime.now().isoformat()
            }
            
            # Save encrypted vault
            vault_data = CryptoEngine.encrypt_aes256gcm(self.encryption_key, json.dumps(self.passwords))
            self.vault_file.write_text(json.dumps(vault_data, indent=2))
            
            print(f"✓ Added {service}")
            return True
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
    
    def list(self) -> bool:
        if not self.is_unlocked:
            print("❌ Vault locked")
            return False
        
        if not self.passwords:
            print("📭 No passwords")
            return True
        
        print("\n" + "="*80)
        print(f"{'Service':<20} {'Username':<30} {'Added':<20}")
        print("="*80)
        
        for entry_id, entry in sorted(self.passwords.items()):
            added = datetime.fromisoformat(entry["added_at"]).strftime("%Y-%m-%d %H:%M")
            print(f"{entry['service']:<20} {entry['username']:<30} {added:<20}")
        
        print("="*80 + "\n")
        return True
    
    def get(self, service: str) -> bool:
        if not self.is_unlocked:
            print("❌ Vault locked")
            return False
        
        matches = [e for e in self.passwords.values() if service.lower() in e["service"].lower()]
        
        if not matches:
            print(f"❌ Not found: {service}")
            return False
        
        if len(matches) > 1:
            print("Multiple matches:")
            for e in matches:
                print(f" - {e['service']}")
            return False
        
        e = matches[0]
        print(f"\nService: {e['service']}")
        print(f"Username: {e['username']}")
        print(f"Password: {e['password']}\n")
        return True
    
    def delete(self, service: str) -> bool:
        if not self.is_unlocked:
            print("❌ Vault locked")
            return False
        
        matches = [(k, v) for k, v in self.passwords.items() if service.lower() in v["service"].lower()]
        
        if not matches:
            print(f"❌ Not found: {service}")
            return False
        
        if len(matches) > 1:
            print("Multiple matches")
            return False
        
        entry_id, entry = matches[0]
        confirm = input(f"Delete {entry['service']}? (yes/no): ").lower()
        
        if confirm != "yes":
            print("Cancelled")
            return False
        
        del self.passwords[entry_id]
        vault_data = CryptoEngine.encrypt_aes256gcm(self.encryption_key, json.dumps(self.passwords))
        self.vault_file.write_text(json.dumps(vault_data, indent=2))
        
        print(f"✓ Deleted {entry['service']}")
        return True