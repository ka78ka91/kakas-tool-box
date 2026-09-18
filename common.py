import os
import sys
import json
import logging
import subprocess
from logging.handlers import RotatingFileHandler


# ================= 路径 =================
# 打包后 __file__ 指向 exe 内部虚拟路径，必须用 sys.executable
if getattr(sys, "frozen", False):
    BASE = os.path.dirname(sys.executable)
else:
    BASE = os.path.dirname(os.path.abspath(__file__))

GUARD = os.path.join(BASE, "guard.py")
LOCK = os.path.join(BASE, "guard.lock")
GUARD_PID = os.path.join(BASE, "guard.pid")
LOG_FILE = os.path.join(BASE, "taskmgr.log")
WINDOW_TITLE = "工具箱"

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

APP_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")),
                       "Toolbox")
CONFIG_FILE = os.path.join(APP_DIR, "config.json")

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "Toolbox"


# ================= 日志 =================
logger = logging.getLogger("toolbox")
logger.setLevel(logging.INFO)
if not logger.handlers:
    try:
        _h = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000,
                                 backupCount=5, encoding="utf-8")
        _h.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(_h)
    except Exception:
        # 日志文件写不了（权限等）就只输出到控制台
        _h = logging.StreamHandler()
        _h.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(_h)


# ================= 全局 =================
quitting = False

_main_root = None
_toast_widgets = []


def set_main_root(root):
    global _main_root
    _main_root = root


# ================= 工具函数 =================
def is_pid_alive(pid):
    try:
        import psutil
        return psutil.pid_exists(pid)
    except Exception:
        return False


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def write_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass


def load_config():
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            cfg.setdefault("theme", "light")
            cfg.setdefault("topmost", True)
            cfg.setdefault("prevent_minimize", True)
            cfg.setdefault("minimize_to_tray", False)
            cfg.setdefault("autostart", False)
            return cfg
    except Exception:
        pass
    return {
        "theme": "light",
        "topmost": True,
        "prevent_minimize": True,
        "minimize_to_tray": False,
        "autostart": False,
    }


def save_config(cfg):
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"保存配置失败: {e}")


# ================= 开机自启 =================
def get_autostart_command():
    if getattr(sys, "frozen", False):
        # 打包后：直接用 exe 的路径
        return f'"{sys.executable}"'
    else:
        # 源码运行：pythonw.exe main.py
        py_dir = os.path.dirname(sys.executable)
        pythonw = os.path.join(py_dir, "pythonw.exe")
        if not os.path.exists(pythonw):
            pythonw = sys.executable
        main_py = os.path.join(BASE, "main.py")
        return f'"{pythonw}" "{main_py}"'


def is_autostart_enabled():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY)
        try:
            val, _ = winreg.QueryValueEx(key, RUN_NAME)
            return bool(val)
        except FileNotFoundError:
            return False
        finally:
            winreg.CloseKey(key)
    except Exception:
        return False


def enable_autostart():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                             winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, RUN_NAME, 0, winreg.REG_SZ,
                          get_autostart_command())
        winreg.CloseKey(key)
        logger.info("已开启开机自启")
        return True
    except Exception as e:
        logger.error(f"开启自启失败: {e}")
        return False


def disable_autostart():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                             winreg.KEY_SET_VALUE)
        try:
            winreg.DeleteValue(key, RUN_NAME)
        except FileNotFoundError:
            pass
        winreg.CloseKey(key)
        logger.info("已关闭开机自启")
        return True
    except Exception as e:
        logger.error(f"关闭自启失败: {e}")
        return False


# ================= Toast =================
def toast(message, level="info", duration=3000):
    if _main_root is None:
        print(f"[{level}] {message}")
        return
    try:
        _main_root.after(0, lambda: _show_toast(
            _main_root, message, level, duration))
    except Exception:
        pass


def _show_toast(root, message, level, duration):
    import tkinter as tk
    colors = {
        "info":    ("#2d6cdf", "#eef3ff"),
        "success": ("#1a7f37", "#e6f7ea"),
        "warn":    ("#8a6d3b", "#fff6dc"),
        "error":   ("#a11",    "#ffdede"),
    }
    fg, bg = colors.get(level, colors["info"])

    top = tk.Toplevel(root)
    top.overrideredirect(True)
    top.attributes("-topmost", True)
    top.configure(bg=bg)

    label = tk.Label(top, text=message, bg=bg, fg=fg,
                     font=("Microsoft YaHei", 10),
                     padx=16, pady=10, justify=tk.LEFT)
    label.pack()

    root.update_idletasks()
    w = label.winfo_reqwidth()
    h = label.winfo_reqheight()
    x = root.winfo_x() + root.winfo_width() - w - 20
    y = root.winfo_y() + 40
    top.geometry(f"{w}x{h}+{x}+{y}")

    _toast_widgets.append(top)

    def _close():
        try:
            top.destroy()
        except Exception:
            pass
        try:
            _toast_widgets.remove(top)
        except ValueError:
            pass

    top.after(duration, _close)
    top.bind("<Button-1>", lambda e: _close())