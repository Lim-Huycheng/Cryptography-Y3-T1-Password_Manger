from .vault import PasswordVault
from .masked_input import masked_input
from .color import UI

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
def prompt_master_credentials(init: bool = False):
    email = input("Email: ").strip().lower()
    if not email:
        UI.err("Email cannot be empty")
        return prompt_master_credentials(init)
    if init:
        UI.warn("⚠ IMPORTANT: Choose a strong master password. "
                "It should be long, unique, and hard to guess, because it protects your entire vault!")
    while True:
        password = masked_input("Master password: ").strip()
        if password:
            return email, password
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
            email, master = prompt_master_credentials(init=True)
            vault.initialize(master, email)
        elif cmd == "unlock":
            if not vault.config_file.exists():
                UI.err("Vault not initialized")
                continue
            email, master = prompt_master_credentials()
            vault.unlock(master, email)
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
            username = input("Username: ").strip()
            password = masked_input("Password: ").strip()
            if not service or not username or not password:
                UI.err("Service, username, and password are required")
                continue
            vault.add(service, username, password)
        elif cmd == "update":
            if not vault.is_unlocked:
                UI.err("Vault locked")
                continue
            service = input("Service: ").strip()
            new_username = input("New username (blank = keep): ").strip() or None
            new_password = masked_input("New password (blank = keep): ").strip() or None
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
