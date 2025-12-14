from getpass import getpass
from .vault import PasswordVault

def show_help():
    print("""
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

def run():
    vault = PasswordVault()
    show_help()

    while True:
        prompt = "🔓> " if vault.is_unlocked else "🔒> "
        cmd = input(prompt).strip()

        if cmd == "init":
            vault.initialize(getpass("Master password: "))
        elif cmd == "unlock":
            vault.unlock(getpass("Master password: "))
        elif cmd == "lock":
            vault.lock()
        elif cmd == "add":
            vault.add(
                input("Service: "),
                input("Username: "),
                getpass("Password: ")
            )
        elif cmd == "update":
            vault.update(
                input("Service: "),
                input("New username (blank = keep): ") or None,
                getpass("New password (blank = keep): ") or None
            )
        elif cmd == "list":
            vault.list()
        elif cmd.startswith("get "):
            vault.get(cmd.split(" ", 1)[1])
        elif cmd.startswith("delete "):
            vault.delete(cmd.split(" ", 1)[1])
        elif cmd == "help":
            show_help()
        elif cmd in ("exit", "quit"):
            print("Goodbye 👋")
            break
        else:
            print("❌ Unknown command (type 'help')")
