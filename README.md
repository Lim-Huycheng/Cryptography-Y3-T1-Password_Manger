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
- 🔐 Strong encryption
   - Argon2id for master password key derieved
   - HKDF key stretching
   - AES-256-GCM authenticated encryption
   - Additional HMAC for integrity verification
- CRUD operations: **add, update, delete, list, get**.
- 📦 Fully offline
   - No network access
   - No cloud dependencies
- 🧠 Single master password 
   - Protects the entire vault
- 📋 Secure clipboard handling
   - Passwords copied temporarily
   - Clipboard auto-clears after a timeout
- 🗂️ Local file storage
   - Encrypted vault stored as JSON
   - Separate configuration file for authentication metadata

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
- Python 3.10+
--- 

1. Clone the repository:
```bash
git clone <repo-url>
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
python -m pw_manager
```
Commmands
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
> init
Email: user@example.com
Master password: ********

> unlock
Email: user@example.com
Master password: ********

> add
Service: github
Username: myuser
Password: ********

> list
Service              | Username
--------------------+--------------------
github               | myuser

> get github
(Password copied to clipboard, clears in 10s)

> lock
Vault locked

```