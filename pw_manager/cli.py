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
  get <service>    Copy password to clipboard
  delete <service> Delete entry
  help             Show help
  exit             Quit
""")

def run():
    vault = PasswordVault()

    print("\n" + "=" * 80)
    print("🔐 Password Manager")
    print("=" * 80 + "\n")

    show_help()

    while True:
        try:
            prompt = "🔓" if vault.is_unlocked else "🔒"
            user_input = input(f"{prompt}> ").strip()
            if not user_input:
                continue

            parts = user_input.split(maxsplit=1)
            command = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else None

            if command == "init":
                vault.initialize(getpass("Master password: "))

            elif command == "unlock":
                vault.unlock(getpass("Master password: "))

            elif command == "lock":
                vault.lock()

            elif command == "add":
                if not vault.is_unlocked:
                    print("❌ Unlock vault first")
                    continue
                vault.add(
                    input("Service: "),
                    input("Username: "),
                    getpass("Password: ")
                )

            elif command == "update":
                vault.update(
                    input("Service: "),
                    input("New username (blank = keep): ") or None,
                    getpass("New password (blank = keep): ") or None
                )

            elif command == "list":
                vault.list()

            elif command == "get":
                if arg:
                    vault.get(arg)
                else:
                    print("❌ Usage: get <service>")

            elif command == "delete":
                if arg:
                    vault.delete(arg)
                else:
                    print("❌ Usage: delete <service>")

            elif command == "help":
                show_help()

            elif command in ("exit", "quit", "q"):
                print("Goodbye! 👋")
                break

            else:
                print("❌ Unknown command")

        except KeyboardInterrupt:
            print("\n\nGoodbye! 👋")
            break

        except Exception as e:
            print(f"❌ Error: {e}")
