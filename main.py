import tkinter as tk
from tkinter import ttk, messagebox
import ctypes
import os
import sys
import json
import subprocess
import threading
import time
import atexit
import psutil

import common
from common import (
    logger, read_json, write_json, GUARD, GUARD_PID, LOCK,
    WINDOW_TITLE, CREATE_NO_WINDOW, is_pid_alive,
    load_config, save_config, toast,
    is_autostart_enabled, enable_autostart, disable_autostart,
)

try:
    import pystray
    from PIL import Image, ImageDraw
    HAS_TRAY = True
except ImportError:
    HAS_TRAY = False

try:
    import win32serviceutil
    HAS_WIN32_SVC = True
except ImportError:
    HAS_WIN32_SVC = False


# ================= 配置 =================
ENABLE_CRITICAL = True
ENABLE_ACL_PROTECT = True
SERVICE_NAME = "ToolboxGuard"


# ================= 服务检测 =================
def service_mode():
    """检测守护服务是否正在运行。"""
    if not HAS_WIN32_SVC:
        return False
    try:
        status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        return status[1] == 4  # SERVICE_RUNNING
    except Exception:
        return False


# ================= 主题 =================
THEMES = {
    "light": {
        "bg":        "#f5f6f8",
        "panel":     "#ffffff",
        "fg":        "#1a1a1a",
        "fg_dim":    "#777777",
        "accent":    "#2d6cdf",
        "border":    "#e2e5ea",
        "entry_bg":  "#ffffff",
        "tree_bg":   "#ffffff",
        "tree_alt":  "#f7f8fa",
        "tree_sel":  "#cfe0ff",
        "danger":    "#a11",
        "warn_bg":   "#fff6dc",
        "warn_fg":   "#8a6d3b",
        "ok_fg":     "#1a7f37",
    },
    "dark": {
        "bg":        "#1e1f22",
        "panel":     "#2b2d31",
        "fg":        "#e6e6e6",
        "fg_dim":    "#9aa0a6",
        "accent":    "#5b9bff",
        "border":    "#3a3d42",
        "entry_bg":  "#23252a",
        "tree_bg":   "#23252a",
        "tree_alt":  "#2b2d31",
        "tree_sel":  "#3a5a9a",
        "danger":    "#ff6b6b",
        "warn_bg":   "#4a3f1a",
        "warn_fg":   "#ffd866",
        "ok_fg":     "#7bd88f",
    },
}


# ================= 关键进程保护 =================
def _enable_debug_privilege():
    try:
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008
        SE_PRIVILEGE_ENABLED = 0x00000002

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", ctypes.c_uint32),
                        ("HighPart", ctypes.c_int32)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", ctypes.c_uint32)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", ctypes.c_uint32),
                        ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        hToken = ctypes.c_void_p()
        if not advapi32.OpenProcessToken(
                kernel32.GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                ctypes.byref(hToken)):
            return False
        try:
            luid = LUID()
            if not advapi32.LookupPrivilegeValueW(
                    None, "SeDebugPrivilege", ctypes.byref(luid)):
                return False
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            if not advapi32.AdjustTokenPrivileges(
                    hToken, False, ctypes.byref(tp), 0, None, None):
                return False
            return ctypes.get_last_error() == 0
        finally:
            kernel32.CloseHandle(hToken)
    except Exception as e:
        logger.error(f"启用 SeDebugPrivilege 失败: {e}")
        return False


def set_critical_process(enable=True):
    try:
        if enable and not _enable_debug_privilege():
            logger.warning("未能启用 SeDebugPrivilege，无法设关键进程")
            return False
        ntdll = ctypes.WinDLL("ntdll")
        ntdll.RtlSetProcessIsCritical(1 if enable else 0, None, False)
        logger.info(f"关键进程标志 -> {enable}")
        return True
    except Exception as e:
        logger.error(f"设置关键进程失败: {e}")
        return False


def _safe_disable_critical():
    try:
        set_critical_process(False)
    except Exception:
        pass


# ================= ACL 进程保护 =================
def protect_process_acl():
    """给自己进程加一条 Deny ACE，拒绝 Everyone 的
    PROCESS_TERMINATE / VM_WRITE / VM_OPERATION。
    效果：普通用户态无法打开进程句柄做终止/写内存操作。
    注意：管理员/SYSTEM 仍可绕过（他们有 WRITE_DAC）。
    """
    if not ENABLE_ACL_PROTECT:
        return False

    try:
        import win32api
        import win32con
        import win32security
    except ImportError:
        logger.warning("pywin32 未安装，跳过 ACL 保护")
        return False

    try:
        pid = os.getpid()
        # 打开自己进程，需要 WRITE_DAC
        hProc = win32api.OpenProcess(
            win32con.WRITE_DAC | win32con.READ_CONTROL,
            False, pid)

        # 取当前 DACL
        sd = win32security.GetSecurityInfo(
            hProc,
            win32security.SE_KERNEL_OBJECT,
            win32security.DACL_SECURITY_INFORMATION)

        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            # 没有 DACL，新建一个
            dacl = win32security.ACL()

        # Everyone 的 SID
        everyone_sid = win32security.CreateWellKnownSid(
            win32security.WinWorldSid, None)

        # 拒绝的权限
        PROCESS_TERMINATE = 0x0001
        PROCESS_VM_OPERATION = 0x0008
        PROCESS_VM_WRITE = 0x0020
        denied = (PROCESS_TERMINATE
                  | PROCESS_VM_OPERATION
                  | PROCESS_VM_WRITE)

        dacl.AddAccessDeniedAce(
            win32security.ACL_REVISION, denied, everyone_sid)

        # 写回
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetSecurityInfo(
            hProc,
            win32security.SE_KERNEL_OBJECT,
            win32security.DACL_SECURITY_INFORMATION,
            None, None, dacl, None)

        try:
            win32api.CloseHandle(hProc)
        except Exception:
            pass

        logger.info("ACL 保护已启用：拒绝 Everyone 的 "
                    "PROCESS_TERMINATE/VM_WRITE/VM_OPERATION")
        return True

    except Exception as e:
        logger.error(f"ACL 保护失败: {e}")
        return False


# ================= 主题管理 =================
class ThemeManager:
    def __init__(self, root, theme_name="light"):
        self.root = root
        self.style = ttk.Style(root)
        self.theme_name = theme_name
        self._apply_ttk_style()

    @property
    def c(self):
        return THEMES.get(self.theme_name, THEMES["light"])

    def _apply_ttk_style(self):
        c = self.c
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        self.style.configure(
            "Treeview",
            background=c["tree_bg"],
            fieldbackground=c["tree_bg"],
            foreground=c["fg"],
            rowheight=24,
            borderwidth=0,
        )
        self.style.map(
            "Treeview",
            background=[("selected", c["tree_sel"])],
            foreground=[("selected", c["fg"])],
        )
        self.style.configure(
            "Treeview.Heading",
            background=c["panel"],
            foreground=c["fg"],
            relief="flat",
            borderwidth=0,
        )
        self.style.map("Treeview.Heading",
                       background=[("active", c["tree_alt"])])

        self.style.configure("TNotebook",
                             background=c["bg"], borderwidth=0)
        self.style.configure("TNotebook.Tab",
                             background=c["panel"],
                             foreground=c["fg"],
                             padding=(14, 6))
        self.style.map("TNotebook.Tab",
                       background=[("selected", c["bg"])],
                       foreground=[("selected", c["accent"])])

        self.style.configure("Vertical.TScrollbar",
                             background=c["panel"],
                             troughcolor=c["bg"],
                             bordercolor=c["border"],
                             arrowcolor=c["fg_dim"])

        self.style.configure("TEntry",
                             fieldbackground=c["entry_bg"],
                             foreground=c["fg"],
                             bordercolor=c["border"])

        self.style.configure("TCheckbutton",
                             background=c["bg"], foreground=c["fg"])
        self.style.configure("TRadiobutton",
                             background=c["bg"], foreground=c["fg"])

        self.style.configure("TCombobox",
                             fieldbackground=c["entry_bg"],
                             background=c["panel"],
                             foreground=c["fg"])

    def switch(self, theme_name):
        self.theme_name = theme_name
        self._apply_ttk_style()
        self._apply_tk_widgets(self.root)

    def _apply_tk_widgets(self, widget):
        c = self.c
        try:
            cls = widget.winfo_class()
            if cls in ("Frame", "Labelframe", "Toplevel"):
                widget.configure(bg=c["bg"])
            elif cls == "Label":
                widget.configure(bg=c["bg"], fg=c["fg"])
            elif cls == "Button":
                widget.configure(bg=c["panel"], fg=c["fg"],
                                 activebackground=c["tree_alt"],
                                 activeforeground=c["fg"])
            elif cls == "Entry":
                widget.configure(bg=c["entry_bg"], fg=c["fg"],
                                 insertbackground=c["fg"])
            elif cls == "Text":
                widget.configure(bg=c["entry_bg"], fg=c["fg"],
                                 insertbackground=c["fg"])
            elif cls == "PanedWindow":
                widget.configure(bg=c["bg"])
            elif cls == "Canvas":
                widget.configure(bg=c["bg"])
        except Exception:
            pass

        for child in widget.winfo_children():
            self._apply_tk_widgets(child)


# ================= 工具箱主应用 =================
class ToolBoxApp:
    def __init__(self, root):
        self.root = root
        common.set_main_root(root)

        self.root.title(WINDOW_TITLE)
        self.root.geometry("920x620")
        self.root.minsize(760, 520)

        self.config = load_config()
        self._is_service_mode = service_mode()

        if not self._is_service_mode:
            if self.config.get("autostart", False):
                if not is_autostart_enabled():
                    enable_autostart()

        self.theme_mgr = ThemeManager(root, self.config.get("theme", "light"))

        if self.config.get("prevent_minimize", True):
            try:
                hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
                style = ctypes.windll.user32.GetWindowLongW(hwnd, -16)
                style &= ~0x00020000
                ctypes.windll.user32.SetWindowLongW(hwnd, -16, style)
            except Exception:
                pass

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.container = tk.Frame(root)
        self.container.pack(fill=tk.BOTH, expand=True)

        self.home_frame = None
        self.tool_frame = None
        self.current_tool = None

        self.tools = {}
        self._register_tools()

        self._build_home()
        self.tool_frame = tk.Frame(self.container)

        self.show_home()

        self._tray_icon = None
        self._setup_tray()

        if not self._is_service_mode:
            self._start_guard()
            threading.Thread(target=self._watch_guard, daemon=True).start()
        else:
            logger.info("检测到守护服务正在运行，GUI 不再自启守护")

        self.theme_mgr.switch(self.config.get("theme", "light"))

        self.root.after(3000, self._startup_check)

        self._keep_visible()

        self._bind_hotkeys()

    # ---------- 工具注册 ----------
    def _register_tools(self):
        from tool.task_manager import TaskManagerTool
        from tool.window_manager import WindowManagerTool
        from tool.file_unlocker import FileUnlockerTool
        from tool.remote_check import RemoteCheckTool
        from tool.log_viewer import LogViewerTool
        from tool.about import AboutTool
        from tool.browser import BrowserTool
        for cls in (TaskManagerTool, WindowManagerTool,
                    FileUnlockerTool, RemoteCheckTool,
                    LogViewerTool, AboutTool, BrowserTool):
            tool = cls(self)
            self.tools[tool.name] = tool

    # ---------- 供工具间调用的 API ----------
    def open_in_browser(self, url):
        try:
            from tool.browser import open_browser
            open_browser(url)
        except Exception as e:
            logger.error(f"打开隔离浏览器失败: {e}")
            common.toast(f"打开失败: {e}", "error")

    # ---------- 主页 ----------
    def _build_home(self):
        c = self.theme_mgr.c
        self.home_frame = tk.Frame(self.container, bg=c["bg"])
        self._build_home_content(self.home_frame)

    def _build_home_content(self, parent):
        c = self.theme_mgr.c

        header = tk.Frame(parent, bg=c["bg"])
        header.pack(fill=tk.X, padx=40, pady=(36, 6))

        tk.Label(header, text="工具箱",
                 font=("Microsoft YaHei", 26, "bold"),
                 bg=c["bg"], fg=c["fg"]).pack(anchor="w")

        sub = tk.Frame(header, bg=c["bg"])
        sub.pack(fill=tk.X, pady=(6, 0))
        tk.Label(sub, text="选择一个工具开始使用",
                 font=("Microsoft YaHei", 11),
                 bg=c["bg"], fg=c["fg_dim"]).pack(side=tk.LEFT)

        settings = tk.Frame(sub, bg=c["bg"])
        settings.pack(side=tk.RIGHT)

        tk.Label(settings, text="主题:",
                 font=("Microsoft YaHei", 10),
                 bg=c["bg"], fg=c["fg_dim"]).pack(side=tk.LEFT, padx=(0, 4))
        self.theme_var = tk.StringVar(value=self.config.get("theme", "light"))
        theme_combo = ttk.Combobox(
            settings, textvariable=self.theme_var,
            values=["light", "dark"], state="readonly", width=8)
        theme_combo.pack(side=tk.LEFT, padx=(0, 12))
        theme_combo.bind("<<ComboboxSelected>>", self._on_theme_change)

        self.topmost_var = tk.BooleanVar(
            value=self.config.get("topmost", True))
        tk.Checkbutton(
            settings, text="置顶",
            variable=self.topmost_var,
            command=self._on_topmost_change
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.prevent_min_var = tk.BooleanVar(
            value=self.config.get("prevent_minimize", True))
        tk.Checkbutton(
            settings, text="防最小化",
            variable=self.prevent_min_var,
            command=self._on_prevent_min_change
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.min_tray_var = tk.BooleanVar(
            value=self.config.get("minimize_to_tray", False))
        tk.Checkbutton(
            settings, text="最小化到托盘",
            variable=self.min_tray_var,
            command=self._on_min_tray_change
        ).pack(side=tk.LEFT, padx=(0, 10))

        if not self._is_service_mode:
            self.autostart_var = tk.BooleanVar(
                value=self.config.get("autostart", False))
            tk.Checkbutton(
                settings, text="开机自启",
                variable=self.autostart_var,
                command=self._on_autostart_change
            ).pack(side=tk.LEFT)

        scroll_area = tk.Frame(parent, bg=c["bg"])
        scroll_area.pack(fill=tk.BOTH, expand=True, padx=40, pady=(24, 10))

        canvas = tk.Canvas(scroll_area, bg=c["bg"],
                           highlightthickness=0, bd=0)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        vsb = ttk.Scrollbar(scroll_area, orient="vertical",
                            command=canvas.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.configure(yscrollcommand=vsb.set)

        cards = tk.Frame(canvas, bg=c["bg"])
        canvas_window = canvas.create_window(
            (0, 0), window=cards, anchor="nw")

        cards.bind("<Configure>",
                   lambda e: canvas.configure(
                       scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfigure(
                        canvas_window, width=e.width))

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-event.delta / 120), "units")

        canvas.bind("<Enter>",
                    lambda e: canvas.bind_all("<MouseWheel>",
                                              _on_mousewheel))
        canvas.bind("<Leave>",
                    lambda e: canvas.unbind_all("<MouseWheel>"))

        for tool in self.tools.values():
            self._make_tool_card(cards, tool)

        footer = tk.Frame(parent, bg=c["bg"])
        footer.pack(fill=tk.X, padx=40, pady=(0, 24))
        tk.Button(footer, text="退出程序", width=12,
                  font=("Microsoft YaHei", 11, "bold"),
                  command=self.quit_all).pack(side=tk.RIGHT)

    def _make_tool_card(self, parent, tool):
        c = self.theme_mgr.c
        card = tk.Frame(parent, bg=c["panel"], cursor="hand2",
                        highlightbackground=c["border"],
                        highlightthickness=1)
        card.pack(fill=tk.X, pady=8, ipady=4)

        icon_lbl = tk.Label(card, text=tool.icon,
                            font=("Segoe UI Emoji", 30),
                            bg=c["panel"], fg=c["accent"], width=4)
        icon_lbl.pack(side=tk.LEFT, padx=(24, 0), pady=20)

        text_frame = tk.Frame(card, bg=c["panel"])
        text_frame.pack(side=tk.LEFT, fill=tk.X, expand=True,
                        padx=16, pady=20)
        name_lbl = tk.Label(text_frame, text=tool.display_name,
                            font=("Microsoft YaHei", 14, "bold"),
                            bg=c["panel"], fg=c["fg"])
        name_lbl.pack(anchor="w")
        desc_lbl = tk.Label(text_frame, text=tool.description,
                            font=("Microsoft YaHei", 10),
                            bg=c["panel"], fg=c["fg_dim"])
        desc_lbl.pack(anchor="w", pady=(6, 0))

        arrow_lbl = tk.Label(card, text="›",
                             font=("Microsoft YaHei", 26),
                             bg=c["panel"], fg=c["fg_dim"])
        arrow_lbl.pack(side=tk.RIGHT, padx=(0, 24))

        widgets = [card, icon_lbl, text_frame, name_lbl, desc_lbl, arrow_lbl]

        def on_click(_e, name=tool.name):
            self.show_tool(name)

        def on_enter(_e):
            for w in widgets:
                try:
                    w.configure(bg=c["tree_alt"])
                except Exception:
                    pass

        def on_leave(_e):
            for w in widgets:
                try:
                    w.configure(bg=c["panel"])
                except Exception:
                    pass

        for w in widgets:
            w.bind("<Button-1>", on_click)
            w.bind("<Enter>", on_enter)
            w.bind("<Leave>", on_leave)

    # ---------- 设置回调 ----------
    def _on_theme_change(self, _event=None):
        name = self.theme_var.get()
        self.config["theme"] = name
        save_config(self.config)
        self.theme_mgr.switch(name)
        for w in self.home_frame.winfo_children():
            w.destroy()
        self.home_frame.configure(bg=self.theme_mgr.c["bg"])
        self._build_home_content(self.home_frame)
        if self.current_tool:
            self.show_tool(self.current_tool.name)
        toast(f"主题已切换为 {name}", "success")

    def _on_topmost_change(self):
        val = self.topmost_var.get()
        self.config["topmost"] = val
        save_config(self.config)
        try:
            self.root.attributes("-topmost", val)
        except tk.TclError:
            pass
        logger.info(f"强制置顶 -> {val}")
        toast(f"置顶 {'开启' if val else '关闭'}", "info")

    def _on_prevent_min_change(self):
        val = self.prevent_min_var.get()
        self.config["prevent_minimize"] = val
        save_config(self.config)
        try:
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            style = ctypes.windll.user32.GetWindowLongW(hwnd, -16)
            if val:
                style &= ~0x00020000
            else:
                style |= 0x00020000
            ctypes.windll.user32.SetWindowLongW(hwnd, -16, style)
            self.root.withdraw()
            self.root.after(10, self.root.deiconify)
        except Exception as e:
            logger.error(f"切换防最小化失败: {e}")
        logger.info(f"防止最小化 -> {val}")
        toast(f"防止最小化 {'开启' if val else '关闭'}", "info")

    def _on_min_tray_change(self):
        val = self.min_tray_var.get()
        self.config["minimize_to_tray"] = val
        save_config(self.config)
        logger.info(f"最小化到托盘 -> {val}")
        toast(f"最小化到托盘 {'开启' if val else '关闭'}", "info")

    def _on_autostart_change(self):
        val = self.autostart_var.get()
        self.config["autostart"] = val
        save_config(self.config)
        if val:
            ok = enable_autostart()
            toast("已开启开机自启" if ok else "开启自启失败",
                  "success" if ok else "error")
        else:
            ok = disable_autostart()
            toast("已关闭开机自启" if ok else "关闭自启失败",
                  "success" if ok else "error")

    # ---------- 快捷键 ----------
    def _bind_hotkeys(self):
        self.root.bind_all("<F5>", self._hotkey_refresh)
        self.root.bind_all("<Control-f>", self._hotkey_focus_search)
        self.root.bind_all("<Control-F>", self._hotkey_focus_search)
        self.root.bind_all("<Escape>", self._hotkey_escape)
        self.root.bind_all("<Delete>", self._hotkey_delete)
        for i in range(1, 10):
            self.root.bind_all(f"<Control-Key-{i}>",
                               lambda e, n=i: self._hotkey_switch(n))

    def _hotkey_refresh(self, _e=None):
        if self.current_tool and hasattr(self.current_tool, "refresh_processes"):
            try:
                self.current_tool.refresh_processes()
                toast("已刷新", "info", 1200)
            except Exception:
                pass
        elif self.current_tool and hasattr(self.current_tool, "refresh"):
            try:
                self.current_tool.refresh()
                toast("已刷新", "info", 1200)
            except Exception:
                pass
        elif self.current_tool and hasattr(self.current_tool, "start_scan"):
            try:
                self.current_tool.start_scan()
            except Exception:
                pass
        return "break"

    def _hotkey_focus_search(self, _e=None):
        if not self.current_tool:
            return "break"
        for attr in ("search_entry", "search_var"):
            if hasattr(self.current_tool, attr):
                obj = getattr(self.current_tool, attr)
                try:
                    if attr == "search_entry":
                        obj.focus_set()
                        obj.select_range(0, tk.END)
                except Exception:
                    pass
                return "break"
        return "break"

    def _hotkey_escape(self, _e=None):
        if self.current_tool:
            for attr in ("search_var", "path_var"):
                if hasattr(self.current_tool, attr):
                    try:
                        getattr(self.current_tool, attr).set("")
                        return "break"
                    except Exception:
                        pass
            self.show_home()
        return "break"

    def _hotkey_delete(self, _e=None):
        if not self.current_tool:
            return "break"
        for method in ("kill_selected", "close_selected_windows",
                       "kill_selected_processes"):
            if hasattr(self.current_tool, method):
                try:
                    getattr(self.current_tool, method)()
                except Exception:
                    pass
                return "break"
        return "break"

    def _hotkey_switch(self, n):
        names = list(self.tools.keys())
        if 1 <= n <= len(names):
            self.show_tool(names[n - 1])
        return "break"

    # ---------- 页面切换 ----------
    def show_home(self):
        if self.current_tool:
            try:
                self.current_tool.on_hide()
            except Exception:
                pass
            self.current_tool = None
        self.tool_frame.pack_forget()
        for w in self.tool_frame.winfo_children():
            w.destroy()
        self.home_frame.pack(fill=tk.BOTH, expand=True)
        self.root.title(WINDOW_TITLE)

    def show_tool(self, name):
        tool = self.tools.get(name)
        if tool is None:
            return

        if self.current_tool:
            try:
                self.current_tool.on_hide()
            except Exception:
                pass

        for w in self.tool_frame.winfo_children():
            w.destroy()

        self.home_frame.pack_forget()
        self.tool_frame.pack(fill=tk.BOTH, expand=True)
        try:
            self.tool_frame.configure(bg=self.theme_mgr.c["bg"])
        except Exception:
            pass

        tool.build(self.tool_frame)
        self.theme_mgr._apply_tk_widgets(self.tool_frame)

        self.current_tool = tool
        self.root.title(f"{WINDOW_TITLE} - {tool.display_name}")
        try:
            tool.on_show()
        except Exception as e:
            logger.error(f"工具 on_show 失败: {e}")

    # ---------- 关闭 ----------
    def on_close(self):
        pass

    def quit_all(self):
        common.quitting = True
        logger.info("用户请求退出")

        if self.current_tool:
            try:
                self.current_tool.on_hide()
            except Exception:
                pass

        if not self._is_service_mode:
            write_json(LOCK, {"exit": True})
            data = read_json(GUARD_PID)
            if data and data.get("guard_pid"):
                try:
                    psutil.Process(data["guard_pid"]).kill()
                except Exception:
                    pass
            for f in (GUARD_PID, LOCK):
                try:
                    os.remove(f)
                except OSError:
                    pass
        else:
            logger.info("服务模式退出，守护服务保持运行")

        _safe_disable_critical()

        if self._tray_icon is not None:
            try:
                self._tray_icon.stop()
            except Exception:
                pass

        try:
            self.root.destroy()
        except Exception:
            pass
        sys.exit()

    # ---------- 守护 ----------
    def _start_guard(self):
        if common.quitting:
            return
        data = read_json(GUARD_PID)
        if data:
            pid = data.get("guard_pid")
            if pid and is_pid_alive(pid):
                return
        try:
            os.remove(GUARD_PID)
        except OSError:
            pass

        try:
            if getattr(sys, "frozen", False):
                # 打包后：调用同目录下的 Guard.exe
                guard_exe = os.path.join(common.BASE, "Guard.exe")
                if not os.path.exists(guard_exe):
                    logger.error(f"找不到 Guard.exe: {guard_exe}")
                    return
                subprocess.Popen(
                    [guard_exe],
                    creationflags=CREATE_NO_WINDOW)
            else:
                # 源码运行：用 python 启动 guard.py
                subprocess.Popen(
                    [sys.executable, GUARD],
                    creationflags=CREATE_NO_WINDOW)
            logger.info("已启动守护进程")
        except Exception as e:
            logger.error(f"启动守护进程失败: {e}")

    def _watch_guard(self):
        while not common.quitting:
            time.sleep(2)
            if common.quitting:
                break
            data = read_json(GUARD_PID)
            if not data:
                self._start_guard()
                continue
            pid = data.get("guard_pid")
            if not pid or not is_pid_alive(pid):
                self._start_guard()

    # ---------- 置顶 / 防最小化 ----------
    def _keep_visible(self):
        if common.quitting:
            return
        try:
            if self.config.get("minimize_to_tray", False) and \
                    self.root.state() == "withdrawn":
                pass
            else:
                if self.config.get("prevent_minimize", True):
                    if self.root.state() == "iconic":
                        self.root.deiconify()
                if self.config.get("topmost", True):
                    self.root.attributes("-topmost", True)
                else:
                    self.root.attributes("-topmost", False)
        except tk.TclError:
            pass
        self.root.after(2000, self._keep_visible)

    # ---------- 启动自检 ----------
    def _startup_check(self):
        try:
            from tool.remote_check import run_startup_check
            danger, warn, summary = run_startup_check()
            if danger > 0 or warn > 0:
                logger.warning(f"启动自检: {summary}")
                toast(f"安全提醒：{summary}（详见远控检测）",
                      "warn", 6000)
            else:
                logger.info("启动自检: 系统状态正常")
        except Exception as e:
            logger.error(f"启动自检异常: {e}")

    # ---------- 托盘 ----------
    def _setup_tray(self):
        if not HAS_TRAY:
            logger.warning("未安装 pystray / pillow，托盘功能不可用")
            return
        try:
            img = Image.new("RGB", (64, 64), color=(32, 34, 40))
            d = ImageDraw.Draw(img)
            d.rectangle([8, 8, 56, 56], outline=(220, 220, 220), width=3)
            d.line([16, 22, 48, 22], fill=(220, 220, 220), width=3)
            d.line([16, 34, 48, 34], fill=(220, 220, 220), width=3)
            d.line([16, 46, 48, 46], fill=(220, 220, 220), width=3)

            menu = pystray.Menu(
                pystray.MenuItem(
                    "显示窗口",
                    lambda *_: self.root.after(0, self._show_from_tray)),
                pystray.MenuItem(
                    "退出",
                    lambda *_: self.root.after(0, self.quit_all)),
            )
            self._tray_icon = pystray.Icon("toolbox", img, WINDOW_TITLE, menu)
            threading.Thread(target=self._tray_icon.run, daemon=True).start()
            logger.info("托盘图标已启动")
        except Exception as e:
            logger.error(f"启动托盘失败: {e}")

    def _show_from_tray(self):
        try:
            self.root.deiconify()
            self.root.lift()
        except Exception:
            pass


# ================= 入口 =================
def main():
    if os.path.exists(LOCK):
        data = read_json(LOCK)
        if data and data.get("exit"):
            try:
                os.remove(LOCK)
            except OSError:
                pass
        elif data and data.get("main_pid"):
            main_pid = data.get("main_pid")
            if main_pid and is_pid_alive(main_pid):
                sys.exit(0)
            else:
                try:
                    os.remove(LOCK)
                except OSError:
                    pass

    write_json(LOCK, {"main_pid": os.getpid()})

    # 关键进程标志
    if ENABLE_CRITICAL:
        if set_critical_process(True):
            atexit.register(_safe_disable_critical)
        else:
            logger.warning("关键进程保护启用失败（可能不是管理员）")

    # ACL 保护
    protect_process_acl()

    root = tk.Tk()
    ToolBoxApp(root)
    root.mainloop()
def _run_browser_mode(url):
    """当 exe 被用 --browser 参数启动时，进入浏览器模式。"""
    import os
    _HERE = os.path.dirname(os.path.abspath(__file__))
    # 把项目目录加入 sys.path
    if _HERE not in sys.path:
        sys.path.insert(0, _HERE)
    if getattr(sys, "frozen", False):
        # PyInstaller 解压目录
        base = sys._MEIPASS
        if base not in sys.path:
            sys.path.insert(0, base)

    from tool._browser_main import main as browser_main
    browser_main(url)


if __name__ == "__main__":
    # 检查是否有 --browser 参数
    if len(sys.argv) >= 3 and sys.argv[1] == "--browser":
        _run_browser_mode(sys.argv[2])
    else:
        main()
