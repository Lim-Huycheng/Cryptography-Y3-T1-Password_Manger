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
## Installation

### 1. Clone the repository
git clone https://github.com/Lim-Huycheng/Cryptography-Y3-T1-Password_Manger.git
cd Cryptography-Y3-T1-Password_Manger

### 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate     # Windows: venv\Scripts\activate

### 3. Install required dependencies
pip install -r requirements.txt
``` 
## Usage
```bash
python app.py
```

### Main Menu Options
```bash 
==== Secure Password Manager ====
1. Create new vault
2. Load existing vault
3. Exit
```
#### Create a New Vault
```bash 
Enter vault filename: myvault.bin
Create master password: ********
Confirm master password: ********
Vault created successfully!
```
#### Main Menu (Vault Unlocked)
```bash
==================================================  
                PASSWORD MANAGER
================================================== 
Vault Status: UNLOCKED (0 domains)
1. Store credentials
2. Retrieve credentials
3. Delete credentials
4. List domains
5. Save and lock vault
6. Exit
```
##### Example
```bash
Enter domain: CADT.com
Enter gmail: Jennie16@gmail.com
Enter password: ********
Credentials for Cadt.com stored.
```
#### Delete credentials
```bash
Enter domain: CADT.com
CADT.com deleted.
```
#### List domains
```bash
Stored domains (1):
- CADT.com
- Github.com
- Youtube.com
```


