#!/usr/bin/env python3
# teralone_auth.py
# Yêu cầu: Python 3.8+
# Giao diện TUI & Command Mode có màu, hỗ trợ phím mũi tên, multi-select và chuột.
# Không dùng thư viện ngoài, tự implement TOTP và TUI.

import time
import hmac
import hashlib
import struct
import json
import base64
import threading
import sys
import os
import select
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path

# --- Platform Support ---
IS_WINDOWS = (os.name == 'nt')

if IS_WINDOWS:
    import msvcrt
    import ctypes
    from ctypes import wintypes

    def _enable_windows_ansi():
        """Force-enable ANSI/VT100 escape sequence processing on Windows
        consoles (cmd.exe / PowerShell). Falls back silently if it fails
        (e.g. output is redirected to a file)."""
        try:
            ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            STD_OUTPUT_HANDLE = -11
            STD_INPUT_HANDLE = -10
            kernel32 = ctypes.windll.kernel32
            for handle_id in (STD_OUTPUT_HANDLE, STD_INPUT_HANDLE):
                handle = kernel32.GetStdHandle(handle_id)
                mode = wintypes.DWORD()
                if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                    kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
        except Exception:
            pass
        # Legacy fallback trick, harmless if the above already worked.
        try:
            os.system('')
        except Exception:
            pass

    _enable_windows_ansi()

    # Make sure UTF-8 (emojis, Vietnamese diacritics, etc.) prints correctly
    # on Windows consoles instead of raising UnicodeEncodeError.
    for _stream in (sys.stdout, sys.stderr, sys.stdin):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    def win_encrypt(data: bytes) -> bytes:
        import ctypes
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        data_in = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_ubyte)))
        data_out = DATA_BLOB()
        if crypt32.CryptProtectData(ctypes.byref(data_in), "QuickAuthData", None, None, None, 0x01, ctypes.byref(data_out)):
            try:
                return ctypes.string_at(data_out.pbData, data_out.cbData)
            finally:
                kernel32.LocalFree(data_out.pbData)
        return data

    def win_decrypt(data: bytes) -> bytes:
        import ctypes
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        data_in = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_ubyte)))
        data_out = DATA_BLOB()
        if crypt32.CryptUnprotectData(ctypes.byref(data_in), None, None, None, None, 0x01, ctypes.byref(data_out)):
            try:
                return ctypes.string_at(data_out.pbData, data_out.cbData)
            finally:
                kernel32.LocalFree(data_out.pbData)
        return data
else:
    def win_encrypt(data: bytes) -> bytes: return data
    def win_decrypt(data: bytes) -> bytes: return data

# --- Terminal Styles ---
class Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    REVERSE = "\033[7m"
    
    # Foreground
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Background
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"

    # Shortcuts
    HEADER = f"{BOLD}{MAGENTA}"
    OK = f"{BOLD}{GREEN}"
    FAIL = f"{BOLD}{RED}"
    WARN = f"{BOLD}{YELLOW}"
    INFO = f"{BOLD}{CYAN}"
    HL = f"{REVERSE}{CYAN}" # Highlight for menu

# --- Environment Detection ---
IS_COMPILED = getattr(sys, 'frozen', False) or "__compiled__" in globals()

def get_env_info():
    if os.path.exists('/data/data/com.termux'):
        return "Android (Termux)"
    elif IS_WINDOWS:
        return "Windows"
    elif sys.platform == 'darwin':
        return "macOS"
    elif sys.platform == 'linux':
        return "Linux"
    return f"Python ({sys.platform})"

# --- Storage Logic ---
BASE_DIR = Path.home() / ".teralone_auth" if IS_COMPILED else Path(".")
CONFIG_FILE = BASE_DIR / "config.json"

def get_current_user():
    if not CONFIG_FILE.exists(): return "user"
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.loads(f.read())
            return data.get("__current_user__", "user")
    except: return "user"

def get_storage_paths(user=None):
    if user is None: user = get_current_user()
    user_dir = BASE_DIR / user
    try:
        user_dir.mkdir(parents=True, exist_ok=True)
    except: pass
    return user_dir / "auth.json", CONFIG_FILE, user_dir / "token.json"

AUTH_FILE, _, TOKEN_FILE = get_storage_paths()
TIME_STEP = 30
DIGITS = 6
lock = threading.Lock()

def load_data(file_path, decrypt=True):
    if not file_path.exists():
        return {}
    try:
        with open(file_path, "rb") as f:
            raw = f.read()
            if decrypt and IS_WINDOWS and raw:
                try: raw = win_decrypt(raw)
                except: pass
            return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}

def save_data(file_path, data, encrypt=True):
    with lock:
        try:
            if not file_path.parent.exists():
                file_path.parent.mkdir(parents=True, exist_ok=True)
            
            content = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
            if encrypt and IS_WINDOWS:
                try: content = win_encrypt(content)
                except: pass
            
            # Create file with 0600 permissions
            if not file_path.exists():
                file_path.touch(mode=0o600)
            else:
                os.chmod(file_path, 0o600)
            
            with open(file_path, "wb") as f:
                f.write(content)
        except Exception as e:
            print(f"{Style.FAIL}Error saving file: {e}{Style.RESET}")

def load_store():
    auth_data = load_data(AUTH_FILE)
    config_data = load_data(CONFIG_FILE, decrypt=False)
    full_store = auth_data.copy()
    full_store.update(config_data)
    return full_store

def save_store(store):
    # Split: config is keys starting with __, auth is others
    auth_data = {k: v for k, v in store.items() if not k.startswith("__")}
    config_data = {k: v for k, v in store.items() if k.startswith("__")}
    
    save_data(AUTH_FILE, auth_data)
    save_data(CONFIG_FILE, config_data, encrypt=False)

def migrate_old_data():
    old_auth = BASE_DIR / "auth.json"
    old_token = BASE_DIR / "token.json"
    user_dir = BASE_DIR / "user"
    if old_auth.exists() and not (user_dir / "auth.json").exists():
        user_dir.mkdir(parents=True, exist_ok=True)
        try:
            with open(old_auth, "rb") as f:
                data = f.read()
                with open(user_dir / "auth.json", "wb") as f2:
                    f2.write(data)
            if old_token.exists():
                with open(old_token, "rb") as f:
                    data = f.read()
                    with open(user_dir / "token.json", "wb") as f2:
                        f2.write(data)
            print(f" {Style.INFO}Migrated data to `user` profile.{Style.RESET}")
        except Exception as e:
            print(f" {Style.FAIL}Migration error: {e}{Style.RESET}")

migrate_old_data()

# --- TOTP Logic ---
def normalize_base32(s: str) -> str:
    return "".join(s.upper().split()).replace("=", "")

def decode_secret(secret_str: str) -> bytes:
    s = secret_str.strip()
    try:
        cleaned = normalize_base32(s)
        pad = '=' * ((8 - len(cleaned) % 8) % 8)
        return base64.b32decode(cleaned + pad, casefold=True)
    except Exception:
        pass
    try:
        return bytes.fromhex(s)
    except Exception:
        pass
    return s.encode("utf-8")

def totp_code(secret_bytes: bytes, for_time: int = None, digits: int = DIGITS, step: int = TIME_STEP) -> (str, int):
    if for_time is None:
        for_time = int(time.time())
    counter = int(for_time // step)
    b = struct.pack(">Q", counter)
    hmac_hash = hmac.new(secret_bytes, b, hashlib.sha1).digest()
    offset = hmac_hash[-1] & 0x0F
    code_int = struct.unpack(">I", hmac_hash[offset:offset+4])[0] & 0x7FFFFFFF
    code = str(code_int % (10 ** digits)).zfill(digits)
    rem = step - (for_time % step)
    return code, rem

# --- Raw Terminal Input ---
class RawTerminal:
    def __enter__(self):
        if IS_WINDOWS:
            # msvcrt needs no raw-mode setup; the console already delivers
            # keys one at a time. Classic Windows consoles don't support
            # SGR mouse reporting, so we skip enabling it here (menus still
            # work fully with the keyboard).
            return self
        import termios, tty
        self.fd = sys.stdin.fileno()
        self.old_settings = termios.tcgetattr(self.fd)
        tty.setraw(self.fd)
        # Enable mouse reporting (SGR mode)
        sys.stdout.write("\033[?1000h\033[?1006h")
        sys.stdout.flush()
        return self

    def __exit__(self, type, value, traceback):
        if IS_WINDOWS:
            return
        import termios
        # Disable mouse reporting
        sys.stdout.write("\033[?1000l\033[?1006l")
        sys.stdout.flush()
        termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old_settings)

    def get_key(self):
        if IS_WINDOWS:
            return self._get_key_windows()
        if not select.select([sys.stdin], [], [], 0.1)[0]:
            return None
        c = sys.stdin.read(1)
        if c == '\033':
            # Escape sequence
            c2 = sys.stdin.read(1)
            if c2 == '[':
                c3 = sys.stdin.read(1)
                if c3 == 'A': return "UP"
                elif c3 == 'B': return "DOWN"
                elif c3 == 'C': return "RIGHT"
                elif c3 == 'D': return "LEFT"
                elif c3 == '<': # Mouse SGR
                    # Read until 'm' or 'M'
                    mouse_data = ""
                    while True:
                        char = sys.stdin.read(1)
                        mouse_data += char
                        if char in ('m', 'M'): break
                    return ("MOUSE", mouse_data)
            return "ESC"
        elif c == '\r' or c == '\n': return "ENTER"
        elif c == ' ': return "SPACE"
        elif c == '\t': return "TAB"
        elif c == '\x03': return "CTRL_C"
        elif c == '\x7f': return "BACKSPACE"
        return c

    def _get_key_windows(self):
        """msvcrt-based equivalent of the termios/select reader above.
        Polls for ~0.1s (same timeout behaviour as the Unix branch) so
        callers relying on `None` meaning "no key yet" keep working."""
        waited = 0.0
        while not msvcrt.kbhit():
            if waited >= 0.1:
                return None
            time.sleep(0.01)
            waited += 0.01

        ch = msvcrt.getwch()
        # Arrow / function keys arrive as a two-character sequence prefixed
        # with '\x00' or '\xe0'.
        if ch in ('\x00', '\xe0'):
            ch2 = msvcrt.getwch()
            return {
                'H': "UP",
                'P': "DOWN",
                'M': "RIGHT",
                'K': "LEFT",
            }.get(ch2, None)
        elif ch in ('\r', '\n'):
            return "ENTER"
        elif ch == ' ':
            return "SPACE"
        elif ch == '\t':
            return "TAB"
        elif ch == '\x03':
            return "CTRL_C"
        elif ch == '\x08':
            return "BACKSPACE"
        elif ch == '\x1b':
            return "ESC"
        return ch

def parse_mouse_sgr(data):
    # data format: "button;x;yM" or "button;x;ym"
    # button: 0=left click, 32=scroll up, 33=scroll down
    try:
        pressed = data.endswith('M')
        parts = data[:-1].split(';')
        btn = int(parts[0])
        x = int(parts[1])
        y = int(parts[2])
        return btn, x, y, pressed
    except:
        return None

# --- TUI Menu System ---
class TUI:
    @staticmethod
    def banner():
        env_type = "Native" if IS_COMPILED else "Python VM"
        print(f" {Style.HEADER}✨ TerAlone's Auth ✨{Style.RESET}", end="\r\n")
        print(f" {Style.DIM}---------------------{Style.RESET}", end="\r\n")
        print(f" Environment: {Style.INFO}{env_type}{Style.RESET}", end="\r\n")

    @staticmethod
    def clear():
        sys.stdout.write("\033[H\033[2J")
        sys.stdout.flush()

    @staticmethod
    def get_input(prompt, password=False):
        current = ""
        with RawTerminal() as rt:
            while True:
                sys.stdout.write(f"\r\x1b[K {prompt} ")
                if password:
                    sys.stdout.write("*" * len(current))
                else:
                    sys.stdout.write(current)
                sys.stdout.flush()
                
                key = rt.get_key()
                if key == "ENTER":
                    sys.stdout.write("\r\n")
                    sys.stdout.flush()
                    return current
                elif key == "BACKSPACE":
                    current = current[:-1]
                elif key == "CTRL_C":
                    sys.stdout.write("\r\n")
                    raise KeyboardInterrupt
                elif isinstance(key, str) and len(key) == 1:
                    current += key

    @staticmethod
    def smart_input(prompt_char, commands_dict, history=None):
        # commands_dict is {cmd: [args...]}
        if history is None: history = []
        current = ""
        suggestion_idx = 0
        history_idx = len(history)
        with RawTerminal() as rt:
            while True:
                # 1. Suggestions logic
                suggestions = []
                if current:
                    parts = current.split()
                    if " " not in current:
                        # Typing the command
                        suggestions = [c for c in commands_dict.keys() if c.startswith(current.lower())]
                    else:
                        # Typing arguments
                        cmd = parts[0].lower()
                        if cmd in commands_dict:
                            if current.endswith(" "):
                                suggestions = commands_dict[cmd]
                            else:
                                last_part = parts[-1].lower()
                                suggestions = [a for a in commands_dict[cmd] if a.startswith(last_part)]
                
                if suggestion_idx >= len(suggestions): suggestion_idx = 0
                
                parts_for_render = current.split()
                cmd_word = parts_for_render[0].lower() if parts_for_render else ""

                # 2. Render Input Line
                sys.stdout.write(f"\r\x1b[K {Style.BOLD}{prompt_char}{Style.RESET} ")
                if not cmd_word:
                    sys.stdout.write(current)
                elif cmd_word in commands_dict:
                    sys.stdout.write(f"{Style.OK}{cmd_word}{Style.RESET}{current[len(cmd_word):]}")
                else:
                    sys.stdout.write(f"{Style.FAIL}{current}{Style.RESET}")
                
                # 3. Draw suggestions line below
                sys.stdout.write("\n\x1b[K")
                if suggestions:
                    s_line = "   "
                    for i, s in enumerate(suggestions):
                        if i == suggestion_idx:
                            s_line += f"{Style.HL} {s} {Style.RESET} "
                        else:
                            s_line += f"{Style.DIM}{s}{Style.RESET} "
                    sys.stdout.write(s_line)
                
                # 4. Restore cursor to input line
                sys.stdout.write(f"\x1b[A\r\x1b[{3 + len(current)}C")
                sys.stdout.flush()

                key = rt.get_key()
                if key == "ENTER":
                    sys.stdout.write("\r\n\x1b[K\r\n")
                    sys.stdout.flush()
                    return current
                elif key == "BACKSPACE":
                    current = current[:-1]
                    suggestion_idx = 0
                    history_idx = len(history)
                elif key == "TAB":
                    if suggestions:
                        if " " not in current:
                            current = suggestions[suggestion_idx] + " "
                        else:
                            p = current.rsplit(" ", 1)
                            current = p[0] + " " + suggestions[suggestion_idx] + " "
                        suggestion_idx = 0
                elif key == "DOWN":
                    if suggestions:
                        suggestion_idx = (suggestion_idx + 1) % len(suggestions)
                    elif history and history_idx < len(history) - 1:
                        history_idx += 1
                        current = history[history_idx]
                    elif history_idx == len(history) - 1:
                        history_idx = len(history)
                        current = ""
                elif key == "UP":
                    if suggestions:
                        suggestion_idx = (suggestion_idx - 1) % len(suggestions)
                    elif history and history_idx > 0:
                        history_idx -= 1
                        current = history[history_idx]
                elif key == "RIGHT":
                    if suggestions: suggestion_idx = (suggestion_idx + 1) % len(suggestions)
                elif key == "LEFT":
                    if suggestions: suggestion_idx = (suggestion_idx - 1) % len(suggestions)
                elif isinstance(key, str) and len(key) == 1:
                    current += key
                    suggestion_idx = 0
                    history_idx = len(history)
                elif key == "CTRL_C":
                    sys.stdout.write("\n\x1b[K\n")
                    raise KeyboardInterrupt
                elif key == "SPACE":
                    current += " "
                    suggestion_idx = 0

    @staticmethod
    def menu(options, title="Menu", multi=False):
        selected_idx = 0
        multi_selected = set()
        
        with RawTerminal() as rt:
            while True:
                TUI.clear()
                TUI.banner()
                print(f" {Style.INFO}{title}:{Style.RESET}", end="\r\n")
                print(f" {Style.DIM}(Arrows: move, Space: select, Enter: confirm, ESC: back){Style.RESET}", end="\r\n")
                print(end="\r\n")
                
                for i, opt in enumerate(options):
                    prefix = ""
                    if multi:
                        prefix = "[x] " if i in multi_selected else "[ ] "
                    
                    if i == selected_idx:
                        print(f" {Style.HL}> {prefix}{opt} {Style.RESET}", end="\r\n")
                    else:
                        print(f"   {prefix}{opt}", end="\r\n")
                
                key = rt.get_key()
                if key == "UP":
                    selected_idx = (selected_idx - 1) % len(options)
                elif key == "DOWN":
                    selected_idx = (selected_idx + 1) % len(options)
                elif key == "SPACE" and multi:
                    if selected_idx in multi_selected:
                        multi_selected.remove(selected_idx)
                    else:
                        multi_selected.add(selected_idx)
                elif key == "ENTER":
                    if multi:
                        return list(multi_selected) if multi_selected else [selected_idx]
                    return selected_idx
                elif key == "ESC" or key == "q":
                    return None
                elif isinstance(key, tuple) and key[0] == "MOUSE":
                    m = parse_mouse_sgr(key[1])
                    if m and m[3]: # Pressed
                        # Lines offset: banner(3) + title(1) + instr(1) + blank(1) = 6 lines.
                        # Option 0 is on line 7.
                        click_y = m[2] - 7
                        if 0 <= click_y < len(options):
                            selected_idx = click_y
                            if multi:
                                if selected_idx in multi_selected: multi_selected.remove(selected_idx)
                                else: multi_selected.add(selected_idx)
                            else:
                                return selected_idx

# --- Sync Logic ---
def sync_request(url, endpoint, payload):
    data = json.dumps(payload).encode('utf-8')
    parsed_url = urllib.parse.urlparse(url)
    headers = {
        'Content-Type': 'application/json',
        'Host': parsed_url.netloc,
        'User-Agent': 'TerAloneClient/1.0'
    }
    
    req = urllib.request.Request(f"{url.rstrip('/')}/{endpoint}", data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as f:
            return json.loads(f.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode('utf-8'))
        except:
            return {"success": False, "message": f"HTTP Error {e.code}"}
    except Exception as e:
        return {"success": False, "message": str(e)}

def refresh_session(store):
    tokens = load_data(TOKEN_FILE)
    at = tokens.get("at")
    rt = tokens.get("rt")
    exp = tokens.get("exp", 0)
    url = store.get("__sync_url__")
    
    if not at or not url: return None

    # 1. Check if AT is locally expired or close to (e.g., within 5 mins)
    if time.time() > exp - 300:
        # Try refresh AT
        res = sync_request(url, "refresh", {"rt": rt, "env": get_env_info()})
        if res.get("success"):
            tokens["at"] = res["at"]
            tokens["rt"] = res["rt"]
            tokens["exp"] = res["exp"]
            save_data(TOKEN_FILE, tokens)
            at = res["at"]
        else:
            return None

    # 2. Get Session Token
    res = sync_request(url, "session", {"at": at})
    if res.get("success"):
        tokens["st"] = res["st"]
        save_data(TOKEN_FILE, tokens)
        return res["st"]
    
    # 3. If session failed (maybe server DB wiped), try one last refresh
    res = sync_request(url, "refresh", {"rt": rt})
    if res.get("success"):
        tokens["at"] = res["at"]
        tokens["rt"] = res["rt"]
        tokens["exp"] = res["exp"]
        save_data(TOKEN_FILE, tokens)
        res = sync_request(url, "session", {"at": tokens["at"]})
        if res.get("success"):
            tokens["st"] = res["st"]
            save_data(TOKEN_FILE, tokens)
            return res["st"]
    
    return None

def perform_sync(store, force=False):
    if not store.get("__sync_enabled__"): return store
    
    st = refresh_session(store)
    if not st:
        print(f" {Style.FAIL}Sync failed: Session expired or invalid. Please re-setup sync.{Style.RESET}")
        return store
    
    url = store.get("__sync_url__")
    # Prepare data to upload (only accounts, no config)
    accounts = {k: v for k, v in store.items() if not k.startswith("__")}
    
    # On force/initial setup, we definitely send current local accounts to server
    res = sync_request(url, "sync", {"st": st, "data": accounts})
    if res.get("success"):
        # Merge downloaded data into local store
        if res.get("data"):
            # Update local with server data
            store.update(res["data"])
            store["__last_sync__"] = int(time.time())
            save_store(store)
            print(f" {Style.OK}Sync completed! ({len(res['data'])} accounts total){Style.RESET}")
        return store
    else:
        if res.get("message") in ["Invalid/Expired/IP Mismatch", "IP mismatch, session revoked", "Invalid session", "Session expired"]:
            print(f" {Style.FAIL}⚠️ Cảnh báo: Phiên đồng bộ đã bị hủy (có thể do IP thay đổi).{Style.RESET}")
            # Xóa token cũ
            save_data(TOKEN_FILE, {})
            # Tạm dừng sync để tránh loop
            store["__sync_enabled__"] = False
            save_store(store)
            
            # Gợi ý re-login
            if TUI.get_input("Bạn có muốn đăng nhập lại để khôi phục Sync? (y/N): ").lower() == 'y':
                return setup_sync(store)
        else:
            print(f" {Style.FAIL}Sync error: {res.get('message')}{Style.RESET}")
        return store

def check_user_exists(url, user):
    try:
        # Use sync_request (POST) for check_user_exists to bypass GET restrictions
        res = sync_request(url, "check", {"user": user})
        return res.get("exists", False)
    except:
        return False

def setup_sync(store):
    if store.get("__sync_enabled__") is not None:
        return perform_sync(store) # Sync once on startup
    
    while True:
        TUI.clear()
        TUI.banner()
        choice = TUI.menu(["Yes (Enable Sync)", "No (Local Only)"], "Enable Code Sync?")
        if choice == 1 or choice is None:
            store["__sync_enabled__"] = False
            save_store(store)
            return store
        
        url = TUI.get_input(f"{Style.INFO}Server URL (http/https):{Style.RESET}").strip()
        if not url: continue
        if not url.startswith(("http://", "https://")):
            print(f" {Style.FAIL}URL must start with http:// or https://{Style.RESET}")
            time.sleep(1)
            continue
        
        if url.startswith("http://"):
            print(f" {Style.FAIL}⚠️ WARNING: YOU ARE USING INSECURE HTTP!{Style.RESET}")
            print(f" {Style.FAIL}Passwords and TOTP secrets can be intercepted.{Style.RESET}")
            conf = TUI.get_input(f" {Style.WARN}Proceed anyway? (y/N):{Style.RESET}").lower()
            if conf != 'y': continue
        
        user = TUI.get_input(f"{Style.INFO}Username:{Style.RESET}").strip()
        if not user: continue
        
        exists = check_user_exists(url, user)
        if exists:
            pwd = TUI.get_input(f"{Style.INFO}Password:{Style.RESET}", password=True)
            res = sync_request(url, "auth", {"user": user, "pass": pwd, "action": "login", "env": get_env_info()})
        else:
            print(f" {Style.WARN}User not found. Creating new account...{Style.RESET}")
            pwd = TUI.get_input(f"{Style.INFO}Create a new password:{Style.RESET}", password=True)
            pwd_conf = TUI.get_input(f"{Style.INFO}Submit your password:{Style.RESET}", password=True)
            if pwd != pwd_conf:
                print(f" {Style.FAIL}Passwords do not match!{Style.RESET}")
                time.sleep(2)
                continue
            res = sync_request(url, "auth", {"user": user, "pass": pwd, "action": "register", "env": get_env_info()})
            
        if res.get("success"):
            store["__sync_enabled__"] = True
            store["__sync_url__"] = url
            store["__sync_user__"] = user
            save_store(store)
            
            # Save tokens
            save_data(TOKEN_FILE, {"at": res["at"], "rt": res["rt"], "exp": res["exp"]})
            
            print(f" {Style.OK}Sync configured successfully!{Style.RESET}")
            time.sleep(1)
            return perform_sync(store)
        else:
            print(f" {Style.FAIL}Error: {res.get('message')}{Style.RESET}")
            time.sleep(2)

# --- Logic Actions ---
def show_live_otps(store, keys):
    if not keys: return
    stop_event = threading.Event()
    def wait_input():
        with RawTerminal(): # temporarily enter raw to catch any key
            if IS_WINDOWS:
                msvcrt.getwch()
            else:
                sys.stdin.read(1)
            stop_event.set()
    
    t = threading.Thread(target=wait_input, daemon=True)
    t.start()
    
    try:
        while not stop_event.is_set():
            TUI.clear()
            TUI.banner()
            print(f"{Style.INFO}🔑 Live codes (Press any key to stop):{Style.RESET}", end="\r\n")
            print(end="\r\n")
            
            now = int(time.time())
            min_rem = TIME_STEP
            for k in keys:
                secret = store[k]
                try:
                    code, rem = totp_code(decode_secret(secret), now)
                    min_rem = min(min_rem, rem)
                    print(f" {Style.BOLD}{k:15}{Style.RESET}: {Style.OK}{code}{Style.RESET} ({rem}s)", end="\r\n")
                except:
                    print(f" {k:15}: {Style.FAIL}Error{Style.RESET}", end="\r\n")
            
            # Progress bar
            bar_len = 20
            filled = int((min_rem / TIME_STEP) * bar_len)
            bar = "█" * filled + "░" * (bar_len - filled)
            sys.stdout.write(f"\r\n [{bar}] Refresh in {min_rem}s\r")
            sys.stdout.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        pass

# --- Command Mode Actions ---
def cmd_imp(args, store, tui=False):
    once = ("--once" in args)
    if once:
        if tui:
            TUI.clear()
            TUI.banner()
        secret = TUI.get_input(f"{Style.INFO}Secret Key>{Style.RESET}").strip()
        if not secret: return store
        try:
            secret_bytes = decode_secret(secret)
            code, rem = totp_code(secret_bytes)
            print(f" {Style.OK}OTP Code: {code}{Style.RESET} (expires in {rem}s)")
            if tui: TUI.get_input(f"{Style.DIM}Press Enter to continue...{Style.RESET}")
        except Exception as e:
            print(f" {Style.FAIL}Error: {e}{Style.RESET}")
            if tui: TUI.get_input(f"{Style.DIM}Press Enter to continue...{Style.RESET}")
        return store

    if tui:
        TUI.clear()
        TUI.banner()
    secret = TUI.get_input(f"{Style.INFO}Secret Key>{Style.RESET}").strip()
    name = TUI.get_input(f"{Style.INFO}Name/Account>{Style.RESET}").strip()
    if not name:
        print(f" {Style.FAIL}Name cannot be empty.{Style.RESET}")
        if tui: TUI.get_input(f"{Style.DIM}Press Enter to continue...{Style.RESET}")
        return store
    store[name] = secret
    save_store(store)
    print(f" {Style.OK}Saved `{name}` successfully! ✨{Style.RESET}")
    store = perform_sync(store)
    if tui: TUI.get_input(f"{Style.DIM}Press Enter to continue...{Style.RESET}")
    return store

def cmd_del(args, store, tui=False):
    if not args and not tui:
        print(f" {Style.WARN}Usage: dkey <name>{Style.RESET}")
        return store
    name = args[0] if args else TUI.get_input(f"{Style.INFO}Name to delete>{Style.RESET}").strip()
    if name in store:
        del store[name]
        save_store(store)
        print(f" {Style.OK}Deleted `{name}` successfully!{Style.RESET}")
        store = perform_sync(store)
    else:
        print(f" {Style.FAIL}Key `{name}` not found.{Style.RESET}")
    if tui: TUI.get_input(f"{Style.DIM}Press Enter to continue...{Style.RESET}")
    return store

def cmd_edit(args, store, tui=False):
    if not args and not tui:
        print(f" {Style.WARN}Usage: ekey <name>{Style.RESET}")
        return store
    old_name = args[0] if args else TUI.get_input(f"{Style.INFO}Name to edit>{Style.RESET}").strip()
    if old_name not in store:
        print(f" {Style.FAIL}Key `{old_name}` not found.{Style.RESET}")
        if tui: TUI.get_input(f"{Style.DIM}Press Enter to continue...{Style.RESET}")
        return store
    
    new_name = TUI.get_input(f"{Style.INFO}New name (empty to keep current):{Style.RESET}").strip()
    new_secret = TUI.get_input(f"{Style.INFO}New secret (empty to keep current):{Style.RESET}").strip()
    
    if new_name or new_secret:
        val = store.pop(old_name)
        store[new_name or old_name] = new_secret or val
        save_store(store)
        print(f" {Style.OK}Updated `{old_name}` successfully!{Style.RESET}")
        store = perform_sync(store)
    
    if tui: TUI.get_input(f"{Style.DIM}Press Enter to continue...{Style.RESET}")
    return store

def cmd_user(args, store, action):
    global AUTH_FILE, TOKEN_FILE
    if action == "auser":
        name = args[0] if args else TUI.get_input(f"{Style.INFO}New profile name:").strip()
        if not name: return store

        url = store.get("__sync_url__")
        if not url:
            url = TUI.get_input(f"{Style.INFO}Sync Server URL:{Style.RESET}").strip()
            if not url: return store

        exists = check_user_exists(url, name)
        if exists:
            pwd = TUI.get_input(f"{Style.INFO}Password for {name}:{Style.RESET}", password=True)
            res = sync_request(url, "auth", {"user": name, "pass": pwd, "action": "login", "env": get_env_info()})
        else:
            print(f" {Style.WARN}User not found. Registering...{Style.RESET}")
            pwd = TUI.get_input(f"{Style.INFO}New Password:{Style.RESET}", password=True)
            res = sync_request(url, "auth", {"user": name, "pass": pwd, "action": "register", "env": get_env_info()})

        if res.get("success"):
            store["__current_user__"] = name
            store["__sync_enabled__"] = True
            store["__sync_url__"] = url
            store["__sync_user__"] = name
            save_store(store)

            AUTH_FILE, _, TOKEN_FILE = get_storage_paths(name)
            save_data(TOKEN_FILE, {"at": res["at"], "rt": res["rt"], "exp": res["exp"]})

            print(f" {Style.OK}Profile `{name}` created and synced.{Style.RESET}")
            return load_store()
        else:
            print(f" {Style.FAIL}Auth failed: {res.get('message')}{Style.RESET}")
            if TUI.get_input("Keep local profile anyway? (y/N): ").lower() != 'y':
                return store
            store["__current_user__"] = name
            save_store(store)
            AUTH_FILE, _, TOKEN_FILE = get_storage_paths(name)
            return load_store()

    elif action == "cuser":
        profiles = sorted([p.name for p in BASE_DIR.iterdir() if p.is_dir() and p.name != "__pycache__"])
        if not profiles: profiles = ["user"]
        idx = TUI.menu(profiles, "Select Profile")
        if idx is not None:
            name = profiles[idx]
            store["__current_user__"] = name
            save_store(store)
            print(f" {Style.OK}Switched to profile `{name}`.{Style.RESET}")
            AUTH_FILE, _, TOKEN_FILE = get_storage_paths(name)
            new_store = load_store()
            return setup_sync(new_store)
    elif action == "duser":
        curr = get_current_user()
        name = args[0] if args else TUI.get_input(f"{Style.INFO}Profile to delete:").strip()
        if name == curr:
            print(f" {Style.FAIL}Cannot delete current profile.{Style.RESET}")
        elif name:
            import shutil
            shutil.rmtree(BASE_DIR / name, ignore_errors=True)
            print(f" {Style.OK}Profile `{name}` deleted.{Style.RESET}")
    return store

def cmd_host(args, store):
    if not args:
        print(f" {Style.INFO}Current Host: {Style.BOLD}{store.get('__sync_url__', 'None')}{Style.RESET}")
    elif args[0] == "change":
        url = args[1] if len(args) > 1 else TUI.get_input(f"{Style.INFO}New Host URL:").strip()
        if url:
            store["__sync_url__"] = url
            save_store(store)
            print(f" {Style.OK}Host changed to `{url}`.{Style.RESET}")
    return store

def cmd_sync_toggle(args, store):
    if not args:
        state = "ON" if store.get("__sync_enabled__") else "OFF"
        print(f" {Style.INFO}Sync is currently {Style.BOLD}{state}{Style.RESET}")
    elif args[0].lower() == "on":
        store["__sync_enabled__"] = True
        save_store(store)
        print(f" {Style.OK}Sync enabled.{Style.RESET}")
        return perform_sync(store)
    elif args[0].lower() == "off":
        store["__sync_enabled__"] = False
        save_store(store)
        print(f" {Style.OK}Sync disabled.{Style.RESET}")
    return store

def cmd_key(args, store):
    if not args:
        print(f" {Style.WARN}Usage: key <all | name> [--loop]{Style.RESET}")
        return
    target = args[0]
    loop = "--loop" in args
    names = sorted([k for k in store.keys() if not k.startswith("__")]) if target == "all" else ([target] if target in store and not target.startswith("__") else [])
    
    if not names:
        print(f" {Style.FAIL}No keys found.{Style.RESET}")
        return

    if loop:
        show_live_otps(store, names)
    else:
        now = int(time.time())
        for n in names:
            code, rem = totp_code(decode_secret(store[n]), now)
            print(f" {Style.BOLD}{n:15}{Style.RESET}: {Style.OK}{code}{Style.RESET} ({rem}s)")

# --- Main Loops ---
def cmd_passwd(store, tui=False):
    if not store.get("__sync_enabled__"):
        print(f" {Style.FAIL}Sync is not enabled for this profile.{Style.RESET}")
        if tui: TUI.get_input(f"{Style.DIM}Press Enter to continue...{Style.RESET}")
        return
    
    url = store.get("__sync_url__")
    user = store.get("__sync_user__")
    
    old_pw = TUI.get_input(f"{Style.INFO}Current Password:{Style.RESET}", password=True)
    new_pw = TUI.get_input(f"{Style.INFO}New Password:{Style.RESET}", password=True)
    new_pw_conf = TUI.get_input(f"{Style.INFO}Confirm New Password:{Style.RESET}", password=True)
    
    if new_pw != new_pw_conf:
        print(f" {Style.FAIL}New passwords do not match!{Style.RESET}")
        if tui: TUI.get_input(f"{Style.DIM}Press Enter to continue...{Style.RESET}")
        return
    
    res = sync_request(url, "passwd", {"user": user, "old_pass": old_pw, "new_pass": new_pw})
    if res.get("success"):
        print(f" {Style.OK}Password updated successfully!{Style.RESET}")
        print(f" {Style.WARN}Please re-login to update tokens.{Style.RESET}")
        # Clear local tokens to force re-login
        save_data(TOKEN_FILE, {})
        if tui: TUI.get_input(f"{Style.DIM}Press Enter to continue...{Style.RESET}")
        return setup_sync(store)
    else:
        print(f" {Style.FAIL}Error: {res.get('message')}{Style.RESET}")
    
    if tui: TUI.get_input(f"{Style.DIM}Press Enter to continue...{Style.RESET}")

def cmd_sessions(args, store, tui=False):
    if not store.get("__sync_enabled__"):
        print(f" {Style.FAIL}Sync is not enabled.{Style.RESET}")
        if tui: TUI.get_input("Press Enter...")
        return
    
    tokens = load_data(TOKEN_FILE)
    at = tokens.get("at")
    url = store.get("__sync_url__")
    
    if args and args[0] == "revoke" and len(args) > 1:
        target_id = args[1]
        confirm = TUI.get_input(f"Confirm revoke session {target_id}? (y/N): ").lower()
        if confirm == 'y':
            rev = sync_request(url, "sessions/revoke", {"at": at, "target_id": target_id})
            if rev.get("success"):
                print(f" {Style.OK}Session {target_id} revoked.{Style.RESET}")
            else:
                print(f" {Style.FAIL}Error: {rev.get('message')}{Style.RESET}")
        return

    res = sync_request(url, "sessions/list", {"at": at})
    if not res.get("success"):
        print(f" {Style.FAIL}Error: {res.get('message')}{Style.RESET}")
        if tui: TUI.get_input("Press Enter...")
        return

    sessions = res["sessions"]
    if tui:
        while True:
            opts = []
            for s in sessions:
                tag = f" {Style.OK}(Current){Style.RESET}" if s["current"] else ""
                opts.append(f"{s['id']} | {s['ip']} | {s['env']}{tag}")
            
            idx = TUI.menu(opts, "Active Sessions (Select to revoke)")
            if idx is None: break
            
            target = sessions[idx]
            if target["current"]:
                print(f" {Style.WARN}Cannot revoke current session here.{Style.RESET}")
                time.sleep(1)
                continue
            
            confirm = TUI.get_input(f"CONFIRM revoke session {target['id']}? (y/N): ").lower()
            if confirm == 'y':
                rev = sync_request(url, "sessions/revoke", {"at": at, "target_id": target["id"]})
                if rev.get("success"):
                    print(f" {Style.OK}Session {target['id']} revoked.{Style.RESET}")
                    sessions.pop(idx)
                else:
                    print(f" {Style.FAIL}Error: {rev.get('message')}{Style.RESET}")
                time.sleep(1)
    else:
        print(f" {Style.HEADER}ID       | IP             | Environment      | Status{Style.RESET}")
        for s in sessions:
            tag = "Current" if s["current"] else ""
            print(f" {s['id']:8} | {s['ip']:14} | {s['env']:16} | {tag}")
        print(f"\n {Style.DIM}Use 'sessions revoke <id>' to revoke.{Style.RESET}")

def run_command_mode(store):
    TUI.clear()
    TUI.banner()
    history = []
    print(f" {Style.HEADER}--- Command mode ---{Style.RESET}")
    print(f" {Style.DIM}Type 'help' for commands, 'exit' to quit.{Style.RESET}")
    while True:
        try:
            # Metadata for suggestions
            keys = sorted([k for k in store.keys() if not k.startswith("__")])
            cmds = {
                "imp": ["--once"],
                "key": ["all", "--loop"] + keys,
                "dkey": keys,
                "ekey": keys,
                "auser": [],
                "cuser": [],
                "duser": [],
                "host": ["change"],
                "sync": ["on", "off"],
                "passwd": [],
                "sessions": [],
                "resync": [],
                "mchange": [],
                "help": [],
                "exit": [],
                "quit": []
            }
            raw = TUI.smart_input(">", cmds, history).strip()
            if not raw: continue
            if not history or history[-1] != raw:
                history.append(raw)
            parts = raw.split()
            cmd = parts[0].lower()
            args = parts[1:]
            
            if cmd in ("exit", "quit"):
                print(f" {Style.OK}Goodbye! 👋{Style.RESET}")
                sys.exit(0)
            elif cmd == "resync":
                store = perform_sync(store)
            elif cmd == "mchange":
                store["__mode__"] = '2'
                save_store(store)
                print(f" {Style.INFO}Mode changed to TUI. Restarting...{Style.RESET}")
                return store, True
            elif cmd == "imp": store = cmd_imp(args, store)
            elif cmd == "key": cmd_key(args, store)
            elif cmd == "dkey": store = cmd_del(args, store)
            elif cmd == "ekey": store = cmd_edit(args, store)
            elif cmd in ("auser", "cuser", "duser"): store = cmd_user(args, store, cmd)
            elif cmd == "host": store = cmd_host(args, store)
            elif cmd == "sync": store = cmd_sync_toggle(args, store)
            elif cmd == "passwd": store = cmd_passwd(store) or store
            elif cmd == "sessions": cmd_sessions(args, store)
            elif cmd == "help":
                print(f"""
 {Style.INFO}Commands:{Style.RESET}
  imp            -> Import and save a key
  imp --once     -> Quick OTP (don't save)
  key all        -> Show all codes
  key <name>     -> Show code for a specific key
  key ... --loop -> Live updating codes
  dkey <name>    -> Delete a key
  ekey <name>    -> Edit a key
  auser <name>   -> Add/switch to a new profile
  cuser          -> Change profile
  duser <name>   -> Delete a profile
  host           -> Show current sync host
  host change    -> Change sync host
  sync <on/off>  -> Toggle sync
  passwd         -> Change sync password
  sessions       -> Manage active login sessions
  resync         -> Synchronize data with server
  mchange        -> Switch to TUI mode
  exit           -> Quit application
""")
            else: print(f" {Style.WARN}Unknown command. Type 'help'.{Style.RESET}")
        except KeyboardInterrupt:
            print()
            sys.exit(0)
    return store, False

def run_tui_mode(store):
    while True:
        options = ["Show live codes", "Import new key", "Edit key", "Delete key", "Profile Management", "Sync & Host", "Change Password", "Manage Sessions", "Resync", "Mode Change", "Exit"]
        choice = TUI.menu(options, "Main Menu")
        
        if choice == 0: # Show keys
            keys = sorted([k for k in store.keys() if not k.startswith("__")])
            if not keys:
                TUI.clear()
                TUI.banner()
                TUI.get_input(f"{Style.WARN}No keys found. Press Enter...{Style.RESET}")
                continue
            sel_indices = TUI.menu(keys, "Select keys (Space to multi-select)", multi=True)
            if sel_indices is not None:
                selected_keys = [keys[i] for i in sel_indices]
                show_live_otps(store, selected_keys)
        elif choice == 1: store = cmd_imp([], store, tui=True)
        elif choice == 2: store = cmd_edit([], store, tui=True)
        elif choice == 3: store = cmd_del([], store, tui=True)
        elif choice == 4: # Profile Management
            p_opts = ["Change Profile (cuser)", "Add Profile (auser)", "Delete Profile (duser)"]
            p_choice = TUI.menu(p_opts, "Profile Management")
            if p_choice == 0: store = cmd_user([], store, "cuser")
            elif p_choice == 1: store = cmd_user([], store, "auser")
            elif p_choice == 2: store = cmd_user([], store, "duser")
        elif choice == 5: # Sync & Host
            s_opts = ["Show Host", "Change Host", "Sync ON", "Sync OFF"]
            s_choice = TUI.menu(s_opts, "Sync & Host")
            if s_choice == 0: cmd_host([], store)
            elif s_choice == 1: store = cmd_host(["change"], store)
            elif s_choice == 2: store = cmd_sync_toggle(["on"], store)
            elif s_choice == 3: store = cmd_sync_toggle(["off"], store)
            if s_choice is not None: TUI.get_input(f"{Style.DIM}Press Enter to continue...{Style.RESET}")
        elif choice == 6: # Password
            store = cmd_passwd(store, tui=True) or store
        elif choice == 7: # Sessions
            cmd_sessions([], store, tui=True)
        elif choice == 8: # Resync
            store = perform_sync(store)
            TUI.get_input(f"{Style.DIM}Press Enter to continue...{Style.RESET}")
        elif choice == 9: # Mode change
            store["__mode__"] = '1'
            save_store(store)
            return store, True
        elif choice == 10 or choice is None:
            TUI.clear()
            TUI.banner()
            print(f" {Style.OK}Goodbye! 👋{Style.RESET}")
            sys.exit(0)
    return store, False

def main():
    store = load_store()
    store = setup_sync(store)
    mode = store.get("__mode__")
    
    while True:
        if mode == '1':
            store, changed = run_command_mode(store)
            if changed: 
                mode = store.get("__mode__")
                continue
        elif mode == '2':
            store, changed = run_tui_mode(store)
            if changed:
                mode = store.get("__mode__")
                continue
        else:
            TUI.clear()
            TUI.banner()
            print(f" {Style.BOLD}Select mode:{Style.RESET}")
            print(f"  {Style.OK}[1]{Style.RESET} Command mode")
            print(f"  {Style.OK}[2]{Style.RESET} TUI mode")
            print(f"  {Style.FAIL}[0]{Style.RESET} Exit")
            
            try:
                choice = input(f"\n {Style.INFO}Choice> {Style.RESET}").strip()
            except KeyboardInterrupt:
                choice = '0'
            
            if choice == '1':
                store["__mode__"] = '1'
                save_store(store)
                mode = '1'
            elif choice == '2':
                store["__mode__"] = '2'
                save_store(store)
                mode = '2'
            elif choice == '0' or choice.lower() == 'exit':
                print(f" {Style.OK}Goodbye! 👋{Style.RESET}")
                break
            else:
                print(f" {Style.WARN}Invalid choice.{Style.RESET}")
                time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Style.OK}Bye!{Style.RESET}")
        sys.exit(0)
