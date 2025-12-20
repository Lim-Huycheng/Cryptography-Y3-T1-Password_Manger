from .vault import PasswordVault
from .masked_input import masked_input
from .color import UI
def show_help():
    UI.info("""
╔════════════════════════════════════════════════════════╗
║              Password Vault Commands                   ║
╚════════════════════════════════════════════════════════╝

  init               Initialize a new vault
  unlock             Unlock vault with master password
  lock               Lock vault
  add                Add new entry
  update             Update existing entry
  list               List all entries
  get <service>      Copy password to clipboard
  delete <service>   Delete entry
  help               Show this help message
  exit, quit         Exit the application
""")
def prompt_master_password(init: bool = False):
    if init:
        UI.warn("⚠ IMPORTANT: Choose a strong master password!")
        UI.warn("  • Use at least 12 characters")
        UI.warn("  • Mix uppercase, lowercase, numbers, and symbols")
        UI.warn("  • This password cannot be recovered if lost")
    while True:
        password = masked_input("Master password: ").strip()
        if password:
            if init:
                confirm = masked_input("Confirm password: ").strip()
                if password != confirm:
                    UI.err("Passwords do not match")
                    continue
            return password
        UI.err("Password cannot be empty")
def run():
    vault = PasswordVault()
    show_help()

    while True:
        try:
            prompt = UI.prompt_unlocked() if vault.is_unlocked else UI.prompt_locked()
            cmd = input(prompt).strip()
            if not cmd:
                continue
            # ==================== Init/Unlock/Lock ==================== #
            if cmd == "init":
                if vault.config_file.exists():
                    UI.err("Vault already exists")
                    continue
                master = prompt_master_password(init=True)
                vault.initialize(master)
            elif cmd == "unlock":
                if not vault.config_file.exists():
                    UI.err("Vault not initialized. Use 'init' first")
                    continue
                if vault.is_unlocked:
                    UI.err("Vault already unlocked")
                    continue
                master = prompt_master_password()
                vault.unlock(master)
            elif cmd == "lock":
                if vault.is_unlocked:
                    vault.lock()
                    UI.ok("✓ Vault locked")
                else:
                    UI.err("Vault is already locked")
            # ==================== Entry Operations ==================== #
            elif cmd == "add":
                if not vault.is_unlocked:
                    UI.err("Vault locked")
                    continue
                service = input("Service name: ").strip()
                username = input("Username: ").strip()
                password = masked_input("Password: ").strip()
                vault.add(service, username, password)
            elif cmd == "update":
                if not vault.is_unlocked:
                    UI.err("Vault locked")
                    continue
                service = input("Service name: ").strip()
                if not service:
                    UI.err("Service name required")
                    continue
                new_username = input("New username (blank = keep): ").strip() or None
                new_password = masked_input("New password (blank = keep): ").strip() or None
                if not new_username and not new_password:
                    UI.err("Nothing to update")
                    continue
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
                # Confirmation
                confirm = input(f"Delete '{service}'? (y/n): ").strip().lower()
                if confirm == "y":
                    vault.delete(service)
                else:
                    UI.info("Cancelled")
            # ==================== Help/Exit ==================== #
            elif cmd == "help":
                show_help()
            elif cmd in ("exit", "quit"):
                if vault.is_unlocked:
                    vault.lock()
                UI.info("Goodbye...")
                break
            else:
                UI.err("Unknown command. Type 'help' for available commands")
        except KeyboardInterrupt:
            print()
            UI.warn("Use 'exit' or 'quit' to leave")
        except Exception as e:
            UI.err(f"Error: {e}")