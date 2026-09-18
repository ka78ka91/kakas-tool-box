import tkinter as tk
from tkinter import ttk, filedialog
import os
import threading
import ctypes
import psutil

import common
from common import logger
from tool import Tool

try:
    from tkinterdnd2 import DND_FILES
    HAS_DND = True
except ImportError:
    HAS_DND = False

from tool import _win_handles


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class FileUnlockerTool(Tool):
    name = "file_unlocker"
    display_name = "文件解锁"
    description = "找出占用文件的进程并结束它"
    icon = "🔓"

    def __init__(self, app):
        super().__init__(app)
        self._scanning = False
        self._holders = {}
        self._target = ""

        self.frame = None
        self.path_var = None
        self.tree = None
        self.status_var = None
        self.banner = None

    def build(self, parent):
        self.frame = parent

        toolbar = tk.Frame(parent)
        toolbar.pack(fill=tk.X, padx=6, pady=(6, 0))

        tk.Button(toolbar, text="← 返回主界面", width=12,
                  font=("Microsoft YaHei", 10),
                  command=self.app.show_home).pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(toolbar, text="文件解锁",
                 font=("Microsoft YaHei", 12, "bold")).pack(side=tk.LEFT)

        tk.Button(toolbar, text="退出程序", width=10,
                  font=("Microsoft YaHei", 12, "bold"),
                  command=self.app.quit_all).pack(side=tk.RIGHT, padx=4)

        if not is_admin():
            self.banner = tk.Label(
                parent,
                text="⚠ 当前非管理员模式：仅启用 RestartManager 引擎，"
                     "可能漏报部分占用进程。建议以管理员身份重新运行。",
                bg="#fff3cd", fg="#8a6d3b",
                font=("Microsoft YaHei", 9), anchor="w",
                padx=10, pady=6)
            self.banner.pack(fill=tk.X, padx=6, pady=(6, 0))

        path_frame = tk.Frame(parent)
        path_frame.pack(fill=tk.X, padx=6, pady=(6, 0))

        tk.Label(path_frame, text="文件:",
                 font=("Microsoft YaHei", 10)).pack(side=tk.LEFT)

        self.path_var = tk.StringVar()
        entry = tk.Entry(path_frame, textvariable=self.path_var,
                         font=("Microsoft YaHei", 10))
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        entry.bind("<Return>", lambda e: self.start_scan())

        tk.Button(path_frame, text="浏览", width=6,
                  command=self._browse).pack(side=tk.LEFT, padx=2)
        tk.Button(path_frame, text="解锁", width=6,
                  font=("Microsoft YaHei", 10, "bold"),
                  command=self.start_scan).pack(side=tk.LEFT, padx=2)

        list_frame = tk.Frame(parent)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        cols = ("name", "pid", "source", "exe")
        self.tree = ttk.Treeview(list_frame, columns=cols,
                                 show="headings",
                                 selectmode="extended")
        for c, t, w, a in [
            ("name", "进程名", 180, "w"),
            ("pid", "PID", 70, "center"),
            ("source", "来源", 80, "center"),
            ("exe", "可执行文件", 520, "w"),
        ]:
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor=a)

        self.tree.tag_configure("system", foreground="#999")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        vsb = ttk.Scrollbar(list_frame, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Button-3>", self._show_context_menu)

        btn_frame = tk.Frame(parent)
        btn_frame.pack(fill=tk.X, padx=6, pady=(0, 6))

        tk.Button(btn_frame, text="结束选中进程", width=14,
                  command=self.kill_selected).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="全部结束", width=12,
                  command=self.kill_all).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="重新扫描", width=12,
                  command=self.start_scan).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="清空", width=8,
                  command=self._clear).pack(side=tk.LEFT, padx=4)

        self.status_var = tk.StringVar(value="就绪")
        tk.Label(parent, textvariable=self.status_var, anchor="w",
                 font=("Microsoft YaHei", 9),
                 relief=tk.SUNKEN, bd=1).pack(fill=tk.X, side=tk.BOTTOM)

        if HAS_DND:
            try:
                self.tree.drop_target_register(DND_FILES)
                self.tree.dnd_bind("<<Drop>>", self._on_drop)
                entry.drop_target_register(DND_FILES)
                entry.dnd_bind("<<Drop>>", self._on_drop)
            except Exception as e:
                logger.error(f"注册拖拽失败: {e}")

    def on_show(self):
        super().on_show()

    def on_hide(self):
        super().on_hide()
        self._scanning = False

    def _on_drop(self, event):
        data = event.data
        paths = []
        if data.startswith("{"):
            parts = []
            buf = ""
            depth = 0
            for ch in data:
                if ch == "{":
                    depth += 1
                    buf = ""
                elif ch == "}":
                    depth -= 1
                    parts.append(buf)
                    buf = ""
                elif depth > 0:
                    buf += ch
                elif ch == " ":
                    if buf:
                        parts.append(buf)
                        buf = ""
                else:
                    buf += ch
            if buf:
                parts.append(buf)
            paths = parts
        else:
            paths = data.split()

        if not paths:
            return
        path = paths[0]
        self.path_var.set(path)
        self.start_scan()

    def _browse(self):
        path = filedialog.askopenfilename(title="选择要解锁的文件")
        if not path:
            path = filedialog.askdirectory(title="选择要解锁的文件夹")
        if path:
            self.path_var.set(path)
            self.start_scan()

    def start_scan(self):
        if self._scanning or not self._visible:
            return
        path = self.path_var.get().strip()
        if not path:
            common.toast("请先选择要解锁的文件", "warn")
            return
        path = os.path.abspath(path)
        if not os.path.exists(path):
            common.toast(f"路径不存在: {path}", "error")
            return

        self._target = path
        self._scanning = True
        self.status_var.set("正在扫描占用进程…")

        for item in self.tree.get_children():
            self.tree.delete(item)
        self._holders.clear()

        threading.Thread(target=self._scan_worker,
                         args=(path,), daemon=True).start()

    def _scan_worker(self, path):
        try:
            use_nt = is_admin()
            holders = _win_handles.find_holders(
                path, use_nt=use_nt,
                progress_cb=self._progress_cb)
        except Exception as e:
            logger.exception(f"文件解锁扫描异常: {e}")
            holders = []
        self.app.root.after(0, lambda: self._apply_holders(path, holders))

    def _progress_cb(self, done, total):
        self.app.root.after(
            0, lambda: self.status_var.set(
                f"扫描中… {done}/{total} 个句柄"))

    def _apply_holders(self, path, holders):
        self._scanning = False
        if not self._visible:
            return

        for h in holders:
            iid = str(h["pid"])
            if self.tree.exists(iid):
                continue
            tags = ("system",) if h.get("is_system") else ()
            self.tree.insert(
                "", tk.END, iid=iid,
                values=(h["name"], h["pid"], h["source"], h["exe"]),
                tags=tags)
            self._holders[iid] = h

        n = len(holders)
        if n == 0:
            self.status_var.set("未发现占用进程 —— 文件可能可以直接删除")
            logger.info(f"文件解锁: {path} 无占用")
        else:
            self.status_var.set(f"发现 {n} 个占用进程")
            logger.info(f"文件解锁: {path} 占用进程 {n} 个")

    def _get_targets(self):
        sel = list(self.tree.selection())
        if not sel:
            common.toast("请先选择要结束的进程", "warn")
            return []
        my_pid = os.getpid()
        guard_pid = None
        d = common.read_json(common.GUARD_PID)
        if d:
            guard_pid = d.get("guard_pid")

        targets = []
        for iid in sel:
            h = self._holders.get(iid)
            if not h:
                continue
            pid = h["pid"]
            if h.get("is_system") or pid in (0, 4):
                common.toast(
                    f"{h['name']} (PID {pid}) 是系统进程，不可结束", "warn")
                continue
            if pid == my_pid:
                common.toast("不能结束自己", "warn")
                continue
            if guard_pid and pid == guard_pid:
                common.toast("不能结束守护进程", "warn")
                continue
            targets.append(h)
        return targets

    def kill_selected(self):
        targets = self._get_targets()
        if not targets:
            return
        self._kill_targets(targets)

    def kill_all(self):
        targets = [h for h in self._holders.values()
                   if not h.get("is_system") and h["pid"] not in (0, 4)]
        if not targets:
            common.toast("没有可结束的进程", "warn")
            return
        self._kill_targets(targets)

    def _kill_targets(self, targets):
        ok, fail = 0, []
        for h in targets:
            pid = h["pid"]
            name = h["name"]
            try:
                p = psutil.Process(pid)
                p.terminate()
                try:
                    p.wait(timeout=3)
                except psutil.TimeoutExpired:
                    p.kill()
                ok += 1
                logger.info(f"文件解锁: 已结束 {name} (PID {pid})")
                if self.tree.exists(str(pid)):
                    self.tree.delete(str(pid))
                    self._holders.pop(str(pid), None)
            except Exception as e:
                fail.append(f"{name}({pid}): {e}")
                logger.error(f"结束进程 {name}({pid}) 失败: {e}")

        msg = f"成功结束 {ok} 个进程"
        if fail:
            msg += f"（失败 {len(fail)}）"
        common.toast(msg, "success" if ok else "warn")

        self.app.root.after(400, self.start_scan)

    def _clear(self):
        self.path_var.set("")
        self._target = ""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._holders.clear()
        self.status_var.set("就绪")

    def _open_exe_location(self):
        sel = self.tree.selection()
        if not sel:
            return
        h = self._holders.get(sel[0])
        if not h:
            return
        exe = h.get("exe")
        if exe and os.path.exists(exe):
            import subprocess
            subprocess.Popen(["explorer", "/select,", exe])
        else:
            common.toast("无法定位可执行文件", "warn")

    def _copy_exe(self):
        sel = self.tree.selection()
        if not sel:
            return
        h = self._holders.get(sel[0])
        if not h:
            return
        try:
            self.app.root.clipboard_clear()
            self.app.root.clipboard_append(h.get("exe") or "")
            self.app.root.update()
        except Exception:
            pass

    def _lookup_vt(self):
        path = self.path_var.get().strip()
        if not path or not os.path.exists(path):
            common.toast("请先选择文件", "warn")
            return
        if not os.path.isfile(path):
            common.toast("只支持文件，不支持文件夹", "warn")
            return

        self.status_var.set("正在计算 SHA256…")

        def worker():
            import hashlib
            try:
                h = hashlib.sha256()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        h.update(chunk)
                digest = h.hexdigest()
            except Exception as e:
                logger.error(f"计算哈希失败: {e}")
                digest = ""

            def done():
                if not digest:
                    self.status_var.set("计算哈希失败")
                    common.toast("计算哈希失败", "error")
                    return
                self.status_var.set(f"SHA256: {digest}")
                self.app.open_in_browser(
                    f"https://www.virustotal.com/gui/file/{digest}")

            self.app.root.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

    def _show_context_menu(self, event):
        row = self.tree.identify_row(event.y)
        if row and row not in self.tree.selection():
            self.tree.selection_set(row)

        menu = tk.Menu(self.app.root, tearoff=0)
        menu.add_command(label="结束进程", command=self.kill_selected)
        menu.add_separator()
        menu.add_command(label="打开文件位置", command=self._open_exe_location)
        menu.add_command(label="复制路径", command=self._copy_exe)
        menu.add_separator()
        menu.add_command(label="计算哈希并查 VirusTotal",
                         command=self._lookup_vt)
        menu.add_separator()
        menu.add_command(label="重新扫描", command=self.start_scan)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()