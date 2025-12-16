import pyperclip
import threading
import time

class ClipboardManager:
    @staticmethod
    def copy_and_clear(secret: str, timeout: int = 10):
        pyperclip.copy(secret)
        print(f"📋 Password copied (clears in {timeout}s)")

        def clear():
            time.sleep(timeout)
            try:
                if pyperclip.paste() == secret:
                    pyperclip.copy("")
                    print("🧹 Clipboard cleared")
            except Exception:
                pass

        threading.Thread(target=clear, daemon=True).start()
