# 🔐 Password Manager

A **Password Manager** built in Python.  
It uses **Argon2id** for password-based key derivation, **AES-256-GCM** for encryption, and **HMAC** for key separation and verification.

---

## **Table of Contents**
1. [Features](#features)
2. [How It Works](#how-it-works)
3. [Installation](#installation)
4. [Usage](#usage)
---

## **Features**

- Store passwords locally in an encrypted vault (`vault.json`).
- Master password authentication with **key separation**.
- AES-256-GCM encryption for vault entries.
- HMAC-based verification ensures integrity without storing the master password.
- Clipboard support with auto-clear after 15 seconds.
- CRUD operations: **add, update, delete, list, get**.
- Offline and fully self-contained.

## **How It Works**

### **1. Key Derivation**
The master password is never stored. Instead:
```text
Master Password
        |
        v
   Argon2id KDF
        |
      root_key
      /       \
  vault_key   verify_key
     |           |
  AES-GCM Encrypt  HMAC verify
     |           |
   vault.json    config.json
```
---

## Installation
1. Clone the repository:
```bash
git clone <repo-url>
cd password_manager
```
2. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
``` 
4. Install dependencies
```bash
pip install -r requirements.txt
``` 
--- 
## Usage
Run the password manager:
```bash
python -m pasword_manager
```
Commands
```bash
 init             Initialize vault
unlock           Unlock vault
lock             Lock vault
add              Add entry
update           Update entry
list             List entries
get <service>    Copy password to clipboard
delete <service> Delete entry
help             Show help
exit             Quit
```
Examples:
```bash
🔒> init
Master password: ************
✓ Vault initialized

🔒> unlock
Master password: ************
✓ Vault unlocked

🔓> add
Service: github
Username: johndoe
Password: ************
✓ Added

🔓> list
+----------------------+----------------------+
| Service              | Username             |
+----------------------+----------------------+
| github               | johndoe              |
+----------------------+----------------------+

```