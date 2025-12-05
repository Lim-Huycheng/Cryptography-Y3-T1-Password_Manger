# Secure Password Manager CLI

## Introduction
Secure Password Manager CLI is a command-line tool for safely storing and managing credentials. It uses AES-GCM encryption, HMAC verification, and Argon2id for key derivation to ensure that your passwords are stored securely. The application supports creating, loading, and locking encrypted vaults while securely wiping sensitive data from memory.

---

## Requirements
- Python 3.8+
- Packages:
  - `pycryptodome`
  - `argon2-cffi`

---

## Features
- **Vault Management**
  - Create a new encrypted vault
  - Load existing vault with master password
  - Lock and securely wipe vault data
- **Credential Management**
  - Store, retrieve, and delete credentials
  - List all stored domains
- **Security**
  - AES-GCM encryption for data confidentiality
  - HMAC verification for integrity
  - Argon2id for key derivation
  - Secure memory wiping
  - Limited failed login attempts
- **User-Friendly CLI**
  - Interactive terminal interface
  - Password input masking
  - Clear status messages

---

## Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/secure-password-manager.git
cd secure-password-manager

# Create virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install pycryptodome argon2-cffi
``` 
## Usage
```bash
python app.py
```

### Main Menu Options
- Vault Locked
  - Create new vault
  - Load existing vault
  - Exit
- Vault Unlocked
  - Store credentials
  - Retrieve credentials
  - Delete credentials
  - List domains
  - Save and lock vault
  - Exit
