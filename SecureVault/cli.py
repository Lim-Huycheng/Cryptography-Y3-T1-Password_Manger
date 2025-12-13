from getpass import getpass
from .vault import SecureVault
def show_help():
    print("""
Commands:
  init <password>    Initialize vault
  unlock <password>  Unlock vault
  lock               Lock vault
  add                Add password
  list               List passwords
  get <service>      Get password
  delete <service>   Delete password
  exit               Exit
  help               Show this help
    """)
def run():
    vault = SecureVault()

    print("\n" + "=" * 80)
    print("🔐 SecureVault - Offline Password Manager")
    print("   Argon2id | HMAC-SHA256 | AES-256-GCM")
    print("=" * 80 + "\n")

    show_help()

    while True:
        try:
            prompt = "🔓" if vault.is_unlocked else "🔒"
            user_input = input(f"{prompt} > ").strip()

            if not user_input:
                continue

            parts = user_input.split(maxsplit=1)
            command = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else None

            if command == "init":
                password = arg or getpass("Master password: ")
                vault.initialize(password)

            elif command == "unlock":
                password = arg or getpass("Master password: ")
                vault.unlock(password)

            elif command == "lock":
                vault.lock()

            elif command == "add":
                if not vault.is_unlocked:
                    print("❌ Unlock vault first")
                    continue

                service = input("Service: ")
                username = input("Username: ")
                password = getpass("Password: ")
                vault.add(service, username, password)

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

            elif command in ("exit", "quit", "q"):
                print("Goodbye! 👋")
                break

            elif command == "help":
                show_help()

            else:
                print(f"❌ Unknown command: {command}")

        except KeyboardInterrupt:
            print("\n\nGoodbye! 👋")
            break

        except Exception as e:
            print(f"❌ Error: {e}")
