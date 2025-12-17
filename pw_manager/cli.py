from getpass import getpass
from .vault import PasswordVault
from .clipboard import ClipboardManager
from .color import UI
import secrets

def show_help():
    UI.info("""
Commands:
  init             Initialize vault
  unlock           Unlock vault
  lock             Lock vault
  add              Add entry
  update           Update entry
  list             List entries
  get <service>    Copy password
  delete <service> Delete entry
  help             Show help
  exit             Quit
""")
def generate_master_key():
    key = secrets.token_urlsafe(32)
    ClipboardManager.copy_and_clear(key, timeout=30)
    UI.info("GENERATED MASTER KEY (copied to clipboard)")
    UI.warn("SAVE THIS KEY NOW — IT CANNOT BE RECOVERED\n")
    return key

def prompt_master_key(init: bool = False) -> str:
    if init:
        UI.warn("Generate master key automatically? (y/N): ")
        choice = input().strip().lower() 
        if choice == "y":
            return generate_master_key()

    while True:
        pwd = getpass("Master password: ")
        if pwd.strip():
            return pwd
        UI.err("Master password cannot be empty")

def run():
    vault = PasswordVault()
    show_help()
    while True:
        cmd = input( 
            UI.prompt_unlocked() if vault.is_unlocked else UI.prompt_locked()
        ).strip()
        if cmd == "init":
            if vault.config_file.exists():
                UI.err("Vault already exists")
                continue
            master = prompt_master_key(init=True)
            vault.initialize(master)
        elif cmd == "unlock":
            if not vault.config_file.exists():
                UI.err("Vault not initialized")
                continue
            master = prompt_master_key()
            vault.unlock(master)
        elif cmd == "lock":
            if vault.is_unlocked:
                vault.lock()
                UI.ok("Vault locked")
            else:
                UI.err("Vault is already locked")
        elif cmd == "add":
            if not vault.is_unlocked:
                UI.err("Vault locked")
                continue
            service = input("Service: ").strip()
            if not service:
                UI.err("Service cannot be empty")
                continue
            username = input("Username: ").strip()
            if not username:
                UI.err("Username cannot be empty")
                continue
            password = getpass("Password: ").strip()
            if not password:
                UI.err("Password cannot be empty")
                continue
            vault.add(service, username, password)
        elif cmd == "update":
            if not vault.is_unlocked:
                UI.err("Vault locked")
                continue
            service = input("Service: ").strip()
            new_username = input("New username (blank = keep): ").strip() or None
            new_password = getpass("New password (blank = keep): ").strip() or None
            vault.update(service, username=new_username, password=new_password)
        elif cmd == "list":
            vault.list()
        elif cmd.startswith("get "):
            if not vault.is_unlocked:
                UI.err("Vault locked")
                continue
            service = cmd.split(" ", 1)[1].strip()
            if not service:
                UI.err("Please specify a service")
                continue
            vault.get(service)
            UI.ok(f"Password for '{service}' copied to clipboard")
        elif cmd.startswith("delete "):
            if not vault.is_unlocked:
                UI.err("Vault locked")
                continue
            service = cmd.split(" ", 1)[1].strip()
            if not service:
                UI.err("Please specify a service")
                continue
            vault.delete(service)
        elif cmd == "help":
            show_help()
        elif cmd in ("exit", "quit"):
            if vault.is_unlocked:
                vault.lock()
            UI.info("Goodbye...")
            break
        else:
            UI.err("Unknown command (type 'help')")



















