import json
import base64
import os

def load_vault_file(path: str):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"Warning: Error reading vault file: {e}")
        # Try to load backup if main file is corrupted
        backup_path = path + ".bak"
        if os.path.exists(backup_path):
            print("Attempting to load backup vault...")
            try:
                with open(backup_path, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return None

def save_vault_file(path: str, salt: bytes, hmac_key_hash: bytes, encrypted_data: dict):
    to_save = {
        "salt": base64.b64encode(salt).decode(),
        "hmac_key_hash": base64.b64encode(hmac_key_hash).decode(),
        "encrypted_data": encrypted_data
    }
    with open(path, "w") as f:
        json.dump(to_save, f, indent=4)

