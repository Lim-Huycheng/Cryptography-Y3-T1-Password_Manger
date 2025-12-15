from colorama import Fore, Style, init

init(autoreset=True)

class UI:
    @staticmethod
    def ok(msg):
        print(Fore.GREEN + "✓ " + msg)

    @staticmethod
    def err(msg):
        print(Fore.RED + "❌ " + msg)

    @staticmethod
    def warn(msg):
        print(Fore.YELLOW + msg)

    @staticmethod
    def info(msg):
        print(Fore.CYAN + msg)

    @staticmethod
    def prompt_locked():
        return Fore.RED + "🔒> " + Style.RESET_ALL

    @staticmethod
    def prompt_unlocked():
        return Fore.GREEN + "🔓> " + Style.RESET_ALL