import tkinter as tk
from tkinter import ttk, messagebox
import ctypes
from ctypes import wintypes
import os
import subprocess
import psutil

import common
from common import logger
from tool import Tool


# ================= Win32 API =================
user32 = ctypes.WinDLL("user32", use_last_error=True)

EnumWindows = user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(
    wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

IsWindowVisible = user32.IsWindowVisible
GetWindowTextW = user32.GetWindowTextW
GetWindowTextLengthW = user32.GetWindowTextLengthW
GetWindowThreadProcessId = user32.GetWindowThreadProcessId
GetClassNameW = user32.GetClassNameW
IsHungAppWindow = user32.IsHungAppWindow
PostMessageW = user32.PostMessageW
SetForegroundWindow = user32.SetForegroundWindow
IsWindow = user32.IsWindow

GetWindowRect = user32.GetWindowRect
SetWindowPos = user32.SetWindowPos
GetWindowLongW = user32.GetWindowLongW
SetWindowLongW = user32.SetWindowLongW

WM_CLOSE = 0x0010
GWL_EXSTYLE = -20
WS_EX_TOPMOST = 0x00000008
HWND_TOPMOST = -1
HWND_NOTOPMOST = -2
SWP_NOMOVE = 0x0002
SWP_NOSIZE = 0x0001
SWP_NOACTIVATE = 0x0010


class RECT(ctypes.Structure):
    _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                ("right", ctypes.c_long), ("bottom", ctypes.c_long)]


# ================= 过滤 =================
_SKIP_CLASSES = {
    "Default IME", "MSCTFIME UI", "IME",
    "ApplicationManager_ImmersiveShellWindow",
    "Shell_TrayWnd", "Shell_SecondaryTrayWnd",
    "Progman", "WorkerW",
    "Windows.UI.Core.CoreWindow",
}

_SUSPICIOUS_TITLE_WORDS = (
    "广告", "推广", "红包", "福利", "免费领取", "点击下载",
    "澳门", "娱乐城", "彩票",
)


def _is_probably_system_window(title, cls, exe):
    if cls in _SKIP_CLASSES:
        return True
    if not title and not exe:
        return True
    return False


def _is_suspicious_title(title):
    if not title:
        return False
    low = title.lower()
    return any(w in low for w in _SUSPICIOUS_TITLE_WORDS)


# ================= 窗口枚举 =================
def enum_windows(include_hidden=False):
    results = []

    def callback(hwnd, _lparam):
        try:
            visible = bool(IsWindowVisible(hwnd))
            if not visible and not include_hidden:
                return True

            length = GetWindowTextLengthW(hwnd)
            buf = ctypes.create_unicode_buffer(length + 1)
            GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value

            cls_buf = ctypes.create_unicode_buffer(256)
            GetClassNameW(hwnd, cls_buf, 256)
            cls = cls_buf.value

            pid = wintypes.DWORD()
            GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            pid = pid.value

            exe = ""
            name = "未知"
            try:
                p = psutil.Process(pid)
                name = p.name() or "未知"
                try:
                    exe = p.exe() or ""
                except Exception:
                    exe = ""
            except Exception:
                pass

            if _is_probably_system_window(title, cls, exe):
                return True

            try:
                hung = bool(IsHungAppWindow(hwnd))
            except Exception:
                hung = False

            r = RECT()
            try:
                GetWindowRect(hwnd, ctypes.byref(r))
                rect = (r.left, r.top, r.right - r.left, r.bottom - r.top)
            except Exception:
                rect = (0, 0, 0, 0)

            try:
                ex_style = GetWindowLongW(hwnd, GWL_EXSTYLE)
                topmost = bool(ex_style & WS_EX_TOPMOST)
            except Exception:
                topmost = False

            results.append({
                "hwnd": hwnd,
                "title": title or "(无标题)",
                "class": cls,
                "pid": pid,
                "name": name,
                "exe": exe,
                "hung": hung,
                "rect": rect,
                "topmost": topmost,
                "visible": visible,
            })
        except Exception:
            pass
        return True

    EnumWindows(EnumWindowsProc(callback), 0)
    return results


# ================= 工具 =================
class WindowManagerTool(Tool):
    name = "window_manager"
    display_name = "窗口管理"
    description = "查看所有可见窗口，关闭窗口或结束进程"
    icon = "🪟"

    def __init__(self, app):
        super().__init__(app)
        self._windows = {}          # iid -> window dict
        self._search = ""
        self._include_hidden = False
        self._only_hung = False
        self._refresh_job = None

        self.frame = None
        self.tree = None
        self.detail_text = None
        self.status_var = None

    # ---------------- UI ----------------
    def build(self, parent):
        self.frame = parent

        toolbar = tk.Frame(parent)
        toolbar.pack(fill=tk.X, padx=6, pady=(6, 0))

        tk.Button(toolbar, text="← 返回主界面", width=12,
                  font=("Microsoft YaHei", 10),
                  command=self.app.show_home).pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(toolbar, text="窗口管理",
                 font=("Microsoft YaHei", 12, "bold")).pack(side=tk.LEFT)

        tk.Button(toolbar, text="刷新", width=8,
                  command=self.refresh).pack(side=tk.LEFT, padx=(20, 4))

        tk.Button(toolbar, text="关闭选中窗口", width=14,
                  command=self.close_selected_windows
                  ).pack(side=tk.LEFT, padx=4)

        tk.Button(toolbar, text="退出程序", width=10,
                  font=("Microsoft YaHei", 12, "bold"),
                  command=self.app.quit_all).pack(side=tk.RIGHT, padx=4)

        # 搜索行
        filter_frame = tk.Frame(parent)
        filter_frame.pack(fill=tk.X, padx=6, pady=(6, 0))

        tk.Label(filter_frame, text="搜索:",
                 font=("Microsoft YaHei", 10)).pack(side=tk.LEFT)

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._on_search_change)
        tk.Entry(filter_frame, textvariable=self.search_var,
                 font=("Microsoft YaHei", 10)
                 ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        tk.Button(filter_frame, text="清除", width=6,
                  command=lambda: self.search_var.set("")
                  ).pack(side=tk.LEFT)

        self.hidden_var = tk.BooleanVar(value=False)
        tk.Checkbutton(filter_frame, text="显示隐藏窗口",
                       variable=self.hidden_var,
                       command=self._on_filter_toggle
                       ).pack(side=tk.LEFT, padx=(8, 0))

        self.hung_var = tk.BooleanVar(value=False)
        tk.Checkbutton(filter_frame, text="仅无响应",
                       variable=self.hung_var,
                       command=self._on_filter_toggle
                       ).pack(side=tk.LEFT, padx=(8, 0))

        # 主区域
        paned = tk.PanedWindow(parent, orient=tk.HORIZONTAL, sashwidth=5)
        paned.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        tree_frame = tk.Frame(paned)
        paned.add(tree_frame, stretch="always")

        cols = ("title", "name", "pid", "class", "state")
        self.tree = ttk.Treeview(tree_frame, columns=cols,
                                 show="headings",
                                 selectmode="extended")
        for c, t, w, a in [
            ("title", "标题", 320, "w"),
            ("name", "进程", 160, "w"),
            ("pid", "PID", 70, "center"),
            ("class", "窗口类", 180, "w"),
            ("state", "状态", 80, "center"),
        ]:
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor=a)

        self.tree.tag_configure("hung", background="#ffdede")
        self.tree.tag_configure("suspect", background="#fff6dc")
        self.tree.tag_configure("hidden", foreground="#888")

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        detail_frame = tk.LabelFrame(paned, text="详情", width=340)
        paned.add(detail_frame, stretch="never")

        self.detail_text = tk.Text(detail_frame, width=46, wrap="word",
                                   font=("Consolas", 9), state="disabled")
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # 事件
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<Button-3>", self._show_context_menu)

        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        tk.Label(parent, textvariable=self.status_var, anchor="w",
                 font=("Microsoft YaHei", 9),
                 relief=tk.SUNKEN, bd=1).pack(fill=tk.X, side=tk.BOTTOM)

    # ---------------- 生命周期 ----------------
    def on_show(self):
        super().on_show()
        self.refresh()
        self._schedule_refresh()

    def on_hide(self):
        super().on_hide()
        if self._refresh_job is not None:
            try:
                self.app.root.after_cancel(self._refresh_job)
            except Exception:
                pass
            self._refresh_job = None

    # ---------------- 定时刷新 ----------------
    def _schedule_refresh(self):
        if self._refresh_job is not None:
            try:
                self.app.root.after_cancel(self._refresh_job)
            except Exception:
                pass
            self._refresh_job = None
        if not common.quitting and self._visible:
            self._refresh_job = self.app.root.after(5000, self._tick)

    def _tick(self):
        self._refresh_job = None
        if common.quitting or not self._visible:
            return
        self.refresh()
        if not common.quitting and self._visible:
            self._refresh_job = self.app.root.after(5000, self._tick)

    # ---------------- 过滤 ----------------
    def _on_search_change(self, *_):
        self._search = self.search_var.get().strip().lower()
        self._render()

    def _on_filter_toggle(self):
        self._include_hidden = self.hidden_var.get()
        self._only_hung = self.hung_var.get()
        self.refresh()

    # ---------------- 刷新 ----------------
    def refresh(self):
        if common.quitting or not self._visible:
            return

        selected_hwnds = set()
        for iid in self.tree.selection():
            w = self._windows.get(iid)
            if w:
                selected_hwnds.add(w["hwnd"])

        self._windows.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

        self._all = enum_windows(include_hidden=self._include_hidden)
        self._render(keep_selected=selected_hwnds)

        total = len(self._all)
        shown = len(self.tree.get_children())
        self.status_var.set(f"共 {total} 个窗口，显示 {shown} 个")

    def _render(self, keep_selected=None):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._windows.clear()

        n = 0
        for w in getattr(self, "_all", []):
            if self._only_hung and not w["hung"]:
                continue
            if self._search:
                hay = (w["title"] + " " + w["name"] + " " +
                       str(w["pid"]) + " " + w["class"]).lower()
                if self._search not in hay:
                    continue

            iid = str(w["hwnd"])
            state = "无响应" if w["hung"] else ("隐藏" if not w["visible"]
                                                else "正常")
            if w["topmost"]:
                state += " · 置顶"

            tags = []
            if w["hung"]:
                tags.append("hung")
            elif not w["visible"]:
                tags.append("hidden")
            elif _is_suspicious_title(w["title"]):
                tags.append("suspect")

            self.tree.insert(
                "", tk.END, iid=iid,
                values=(w["title"], w["name"], w["pid"], w["class"], state),
                tags=tuple(tags))
            self._windows[iid] = w
            n += 1

        if keep_selected:
            for iid in keep_selected:
                if self.tree.exists(str(iid)):
                    self.tree.selection_add(str(iid))

    # ---------------- 详情 ----------------
    def _on_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        w = self._windows.get(sel[0])
        if not w:
            return
        self._show_details(w)

    def _show_details(self, w):
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", tk.END)

        info = [
            ("标题", w["title"]),
            ("进程", w["name"]),
            ("PID", w["pid"]),
            ("可执行文件", w.get("exe") or "(未知)"),
            ("窗口类", w["class"]),
            ("状态", "无响应" if w["hung"] else "正常"),
            ("可见", "是" if w["visible"] else "否"),
            ("置顶", "是" if w["topmost"] else "否"),
            ("HWND", hex(w["hwnd"])),
            ("位置", f"({w['rect'][0]}, {w['rect'][1]})  "
                     f"尺寸 {w['rect'][2]}×{w['rect'][3]}"),
        ]

        for k, v in info:
            self.detail_text.insert(tk.END, f"{k}:\n", "key")
            self.detail_text.insert(tk.END, f"  {v}\n\n")

        # 命令行
        try:
            cmd = " ".join(psutil.Process(w["pid"]).cmdline())
            self.detail_text.insert(tk.END, "命令行:\n", "key")
            self.detail_text.insert(tk.END, f"  {cmd}\n\n")
        except Exception:
            pass

        self.detail_text.tag_configure(
            "key", foreground="#2d6cdf",
            font=("Microsoft YaHei", 9, "bold"))
        self.detail_text.configure(state="disabled")

    # ---------------- 操作 ----------------
    def close_selected_windows(self):
        sel = list(self.tree.selection())
        if not sel:
            messagebox.showwarning("提示", "请先选择窗口")
            return
        ok = 0
        for iid in sel:
            w = self._windows.get(iid)
            if not w:
                continue
            try:
                PostMessageW(w["hwnd"], WM_CLOSE, 0, 0)
                ok += 1
                logger.info(f"关闭窗口: {w['title']} "
                            f"({w['name']} PID {w['pid']})")
            except Exception as e:
                logger.error(f"关闭窗口失败: {e}")
        self.status_var.set(f"已发送关闭消息给 {ok} 个窗口")
        # 稍等让窗口处理消息
        self.app.root.after(500, self.refresh)

    def kill_selected_processes(self):
        sel = list(self.tree.selection())
        if not sel:
            messagebox.showwarning("提示", "请先选择窗口")
            return

        my_pid = os.getpid()
        guard_pid = None
        d = common.read_json(common.GUARD_PID)
        if d:
            guard_pid = d.get("guard_pid")

        pids = set()
        skipped = []
        for iid in sel:
            w = self._windows.get(iid)
            if not w:
                continue
            pid = w["pid"]
            if pid == my_pid:
                skipped.append(f"{pid} (自己)")
                continue
            if guard_pid and pid == guard_pid:
                skipped.append(f"{pid} (守护进程)")
                continue
            pids.add((pid, w["name"]))

        if not pids:
            messagebox.showwarning("提示",
                                   "没有可结束的进程\n" + "\n".join(skipped))
            return

        ok, fail = 0, []
        for pid, name in pids:
            try:
                p = psutil.Process(pid)
                p.terminate()
                try:
                    p.wait(timeout=3)
                except psutil.TimeoutExpired:
                    p.kill()
                ok += 1
                logger.info(f"结束进程: {name} (PID {pid})")
            except Exception as e:
                fail.append(f"{name}({pid}): {e}")

        msg = f"成功结束 {ok} 个进程"
        if fail:
            msg += "\n失败:\n" + "\n".join(fail[:5])
        if skipped:
            msg += "\n跳过: " + ", ".join(skipped)
        messagebox.showinfo("结果", msg)
        self.refresh()

    def _on_double_click(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        w = self._windows.get(sel[0])
        if not w:
            return
        try:
            if IsWindow(w["hwnd"]):
                SetForegroundWindow(w["hwnd"])
        except Exception:
            pass

    def _toggle_topmost(self):
        sel = self.tree.selection()
        if not sel:
            return
        w = self._windows.get(sel[0])
        if not w:
            return
        try:
            if w["topmost"]:
                SetWindowPos(w["hwnd"], HWND_NOTOPMOST, 0, 0, 0, 0,
                             SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)
            else:
                SetWindowPos(w["hwnd"], HWND_TOPMOST, 0, 0, 0, 0,
                             SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)
        except Exception:
            pass
        self.app.root.after(200, self.refresh)

    def _open_file_location(self):
        sel = self.tree.selection()
        if not sel:
            return
        w = self._windows.get(sel[0])
        if not w:
            return
        exe = w.get("exe")
        if exe and os.path.exists(exe):
            subprocess.Popen(["explorer", "/select,", exe])
        else:
            messagebox.showinfo("提示", "无法定位可执行文件")

    # ---------------- 右键菜单 ----------------
    def _show_context_menu(self, event):
        row = self.tree.identify_row(event.y)
        if row and row not in self.tree.selection():
            self.tree.selection_set(row)

        menu = tk.Menu(self.app.root, tearoff=0)
        menu.add_command(label="关闭窗口", command=self.close_selected_windows)
        menu.add_command(label="结束进程",
                         command=self.kill_selected_processes)
        menu.add_separator()
        menu.add_command(label="切换到该窗口",
                         command=self._on_double_click)
        menu.add_command(label="置顶 / 取消置顶",
                         command=self._toggle_topmost)
        menu.add_separator()
        menu.add_command(label="打开文件所在位置",
                         command=self._open_file_location)
        menu.add_separator()
        menu.add_command(label="刷新", command=self.refresh)

        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()