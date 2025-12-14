import pyperclip
import threading
import time

class ClipboardManager:
    @staticmethod
    def copy_and_clear(secret: str, timeout: int = 15):
        pyperclip.copy(secret)
        print(f"📋 Password copied to clipboard (clears in {timeout}s)")

        def clear_clipboard():
            time.sleep(timeout)
            try:
                if pyperclip.paste() == secret:
                    pyperclip.copy("")
                    print("🧹 Clipboard cleared")
            except Exception:
                pass

        threading.Thread(target=clear_clipboard, daemon=True).start()
