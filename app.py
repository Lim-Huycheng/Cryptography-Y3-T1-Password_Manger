#OFFICIAL 
from getpass import getpass
from keychain import SecureKeychain

class SecurePasswordManagerCLI:
    def __init__(self):
        self.keychain = SecureKeychain()
        self.failed_attempts = 0
        self.max_attempts = 5

    def main_menu(self): 
        while True:
            print("\n" + "=" * 50)
            print("                PASSWORD MANAGER")
            print("=" * 50)

            if not self.keychain.is_initialized:
                print("\nVault Status: LOCKED")
                print("\n1. Create new vault")
                print("2. Load existing vault")
                print("3. Exit")
            else:
                print(f"\nVault Status: UNLOCKED ({self.keychain.get_domain_count()} domains)")
                print("\n1. Store credentials")
                print("2. Retrieve credentials")
                print("3. Delete credentials")
                print("4. List domains")
                print("5. Save and lock vault")
                print("6. Exit")

            choice = input("\nEnter your choice: ").strip()

            if not self.keychain.is_initialized:
                if choice == "1":
                    self.create_vault()
                elif choice == "2":
                    self.load_vault()
                elif choice == "3":
                    print("Goodbye!")
                    break
                else:
                    print("Invalid choice!")
            else:
                if choice == "1":
                    self.store_credentials()
                elif choice == "2":
                    self.retrieve_credentials()
                elif choice == "3":
                    self.delete_credentials()
                elif choice == "4":
                    self.list_domains()
                elif choice == "5":
                    self.lock_vault()
                elif choice == "6":
                    self.keychain.lock_vault()
                    print("Goodbye!")
                    break
                else:
                    print("Invalid choice!")

    def create_vault(self):
        password = getpass("Enter master password: ").strip()
        if len(password) < 8:
            print("Master password should be at least 8 characters!")
            return
        confirm = getpass("Confirm master password: ").strip()
        if password != confirm:
            print("Passwords don't match!")
            return

        if self.keychain.create_vault(password):
            print("Vault created successfully.")
        else:
            print("Failed to create vault!")

    def load_vault(self):
        if self.failed_attempts >= self.max_attempts:
            print(f"Too many failed attempts. Please restart the application.")
        
        password = getpass("Enter master password: ").strip()

        if self.keychain.load_vault(password):
            print("Vault loaded successfully.")
        else:
            self.failed_attempts += 1
            remaining = self.max_attempts - self.failed_attempts
            if remaining > 0:
                print(f"Failed to load vault. {remaining} attempts remaining.") 
            else:
                print("Attempts reached. Please restart the application.")

    def store_credentials(self):
        domain = input("Enter domain: ").strip()
        email = input("Enter email: ").strip()
        password = getpass("Enter password: ").strip()

        if not domain or not email or not password:
            print("All fields are required!")
            return

        if self.keychain.add_credentials(domain, email, password):
            print(f"Credentials for {domain} stored.")
        else:
            print("Failed to store credentials.")

    def retrieve_credentials(self):
        domain = input("Enter domain: ").strip()
        creds = self.keychain.get_credentials(domain)

        if creds:
            print(f"\nCredentials for {domain}:")
            print(f"  Email: {creds['email']}")
            print(f"  Password: {creds['password']}")
        else:
            print("No credentials found.")

    def delete_credentials(self):
        domain = input("Enter domain: ").strip()
        if self.keychain.delete_credentials(domain):
            print(f"{domain} deleted.")
        else:
            print("No such domain found.")

    def list_domains(self):
        domains = self.keychain.list_domains()
        if domains:
            print(f"\nStored domains ({len(domains)}):")
            for d in domains:
                print(" •", d)
        else:
            print("No domains stored.")

    def lock_vault(self):
        self.keychain.lock_vault()

if __name__ == "__main__":
    SecurePasswordManagerCLI().main_menu()
