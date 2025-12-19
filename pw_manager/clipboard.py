import pyperclip
import threading
import time
from .color import UI
from colorama import Fore, Style
class ClipboardManager:
    @staticmethod
    def copy_and_clear(secret: str, timeout: int = 10):
        try:
            pyperclip.copy(secret)
            UI.warn(f"⚠ IMPORTANT: Password copied (clears in {timeout}s)" + Style.RESET_ALL)
        except pyperclip.PyperclipException as e:
            print(Fore.RED + f"❌ Failed to copy to clipboard: {e}" + Style.RESET_ALL)
            return
        def clear():
            time.sleep(timeout)
            try:
                current = pyperclip.paste()
                if current == secret:
                    pyperclip.copy("")
                    print(Fore.CYAN + "Clipboard cleared" + Style.RESET_ALL)
            except Exception:
                pass
        threading.Thread(target=clear, daemon=True).start()
