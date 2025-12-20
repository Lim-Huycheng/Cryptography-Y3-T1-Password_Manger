# Password Manager
A secure, lightweight command-line password manager built for developers and security-conscious users. Store, manage, and retrieve your credentials with confidence. This project is built in Python language. 

---

## **Features**
- Strong encryption
   - Argon2id for master password key derieved
   - HKDF key stretching
   - AES-256-GCM authenticated encryption
   - Additional HMAC for integrity verification
- CRUD operations: **add, update, delete, list, get**.
- Fully offline
   - No network access
   - No cloud dependencies
- Single master password 
   - Protects the entire vault
- Secure clipboard handling
   - Passwords copied temporarily
   - Clipboard auto-clears after a timeout
- Local file storage
   - Encrypted vault stored as JSON
   - Separate configuration file for authentication metadata
- Activites Log: Tracking all user operation with timestamps and status. 
  
  ---
  
## Requirements
- Python 3.10+
- pip (Python package manager)
- Virtual Envirnment (optional but recommend)
  
--- 
## Installation 
1. Clone the repository:
```bash
git clone <repo-url>
```
2. Create a virtual environment
```bash
python -m venv venv
```
3. Activate the virtual environment:
   - Window:
```bash 
venv\Scripts\activate    
```
   - Linux/macOS:
```bash
source venv/bin/activate
```
4. Install dependencies
```bash
pip install -r requirements.txt
``` 
--- 
## Dependencies
```bash
- cryptography
- argon2-cffi
- pyperclip
- colorama
```
## Usage
Run the password manager:
```bash
python -m code
```
Commands:
Add a new password entry:
```bash
> add
Service name: GitHub
Username: john.doe
Password: ••••••••
```
list all stored credential:
```bash
> list
```
Retrieve and copy a password to cllipboard
```bash
> git Github
```
Update an existing entry:
```bash
> update Github
New username (blank = keep): jane.doe
New password (blank = keep): ••••••••
```
View the last recent log entries:
```bash
> audit-log
```
view the last N log entries
```bash
> audit-log 10
```
Display audit statistics and summary:
```bash
> audit-stats
```
Display help menu:
```bash
> help
```
Exit the application
```bash
> exit
```

## Security 

- Master Password: master password cannot be recovered if forgotten. Choose a strong password with at least 12 characters, mixing uppercase, lowercase, numbers, and symbols.
- Encryption: All passwords are encrypted using AES-256-GCM with a 256-bit key derived from  master password using Argon2id.
- Authentication: HMAC-SHA256 is used to verify vault integrity.
- Logs: All operations are logged with timestamps and status for security.
