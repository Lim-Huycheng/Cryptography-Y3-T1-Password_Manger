import sys
def masked_input(prompt: str = "", mask: str = "*") -> str:
    """
    Read password input and display '*' for each character.
    Works on Windows and Unix.
    """
    sys.stdout.write(prompt)
    sys.stdout.flush()
    password = []

    if sys.platform.startswith("win"):
        import msvcrt

        while True:
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):
                print()
                break
            elif ch == "\b":
                if password:
                    password.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
            elif ch == "\x03":
                raise KeyboardInterrupt
            else:
                password.append(ch)
                sys.stdout.write(mask)
                sys.stdout.flush()

    else:
        import termios
        import tty

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)

        try:
            tty.setraw(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch in ("\n", "\r"):
                    print()
                    break
                elif ch == "\x7f":  # Backspace
                    if password:
                        password.pop()
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                elif ch == "\x03":
                    raise KeyboardInterrupt
                else:
                    password.append(ch)
                    sys.stdout.write(mask)
                    sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    return "".join(password)
