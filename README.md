# Password Manager

SecureVault is an **offline password manager** built in Python. It securely stores your passwords using **Argon2id**, **HMAC-SHA256**, and **AES-256-GCM** encryption. All data is stored locally.

---

## Features

- Initialize and unlock a secure vault with a master password
- Add, retrieve, list, and delete passwords for different services
- Offline storage for maximum security
- Strong encryption with AES-256-GCM and HMAC-SHA256
- Password hashing with Argon2id
- Command-line interface (CLI) for easy use

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/SecureVault.git
cd SecureVault
```
2. Create and activate a virtual environment
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
```
3. Install dependencies
```bash
pip install -r requirements.txt
```
---

## Usage 
- Run the CLI:
```bash
python -m SecureVault
```
- You will see a prompt like:
```bash
🔒 > 
```
- Commands
```bash
init <password>    Initialize vault
unlock <password>  Unlock vault
lock               Lock vault
add                Add password
list               List passwords
get <service>      Get password
delete <service>   Delete password
exit               Exit
help               Show this help
```
- init – Create a new vault with a master password.
- unlock – Unlock the vault to access stored passwords.
- lock – Lock the vault.
- add – Add a new password entry (service, username, password).
- list – List all stored services.
- get <service> – Retrieve credentials for a service.
- delete <service> – Remove credentials for a service.
- help – Show CLI commands.
- exit – Exit the program
---

### Example Workflow:
- Initialize the vault
```bash
init
```
- Unlock the vault
```bash 
unlock
```
- Add a new service
```bash
add
Service: Gmail
Username: user@gmail.com
Password: ********
``` 
- List all services
```bash
list
# Get a password
get Gmail
```
 Delete a service
```bash
delete Gmail
```
- Lock the vault
```bash
lock
```
- Exit the CLI
```bash
exit
```

--- 
