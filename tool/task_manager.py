import tkinter as tk
from tkinter import ttk
import os
import time
import subprocess
import threading
import datetime
import json
import psutil

import common
from common import logger, read_json, GUARD_PID, CREATE_NO_WINDOW
from tool import Tool


COLUMNS = ("pid", "name", "cpu", "memory", "status", "username")

_STATUS_MAP = {
    "running": "运行",
    "sleeping": "睡眠",
    "disk-sleep": "磁盘",
    "stopped": "停止",
    "zombie": "僵尸",
    "idle": "空闲",
    "tracing-stop": "跟踪",
    "dead": "死亡",
    "wake-kill": "唤醒",
    "waking": "唤醒中",
    "parked": "挂起",
}

ADVERSARY_TOOLS = {
    "procexp.exe", "procexp64.exe", "processhacker.exe",
    "procmon.exe", "procmon64.exe", "pchunter.exe", "pchunter64.exe",
    "autoruns.exe", "autoruns64.exe", "xuetr.exe", "xuetr64.exe",
    "systeminformer.exe", "ksysteminformer.exe",
}


def _format_mem(mb):
    if mb >= 1024:
        return f"{mb / 1024:.2f} GB"
    return f"{mb:.1f}"


def _run_ps(cmd, timeout=20):
    ps = (
        "$OutputEncoding = [Console]::OutputEncoding = "
        "[Text.Encoding]::UTF8; " + cmd
    )
    r = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-Command", ps],
        capture_output=True, timeout=timeout,
        creationflags=CREATE_NO_WINDOW,
    )
    return r.stdout.decode("utf-8", errors="replace")


class TaskManagerTool(Tool):
    name = "task_manager"
    display_name = "任务管理器"
    description = "查看、搜索、结束系统进程"
    icon = "📋"

    def __init__(self, app):
        super().__init__(app)

        self.search_keyword = ""
        self.sort_column = "memory"
        self.sort_reverse = True
        self.tree_mode = False

        self._process_objects = {}
        self._username_cache = {}
        self._detected_tools = set()
        self._me = psutil.Process(os.getpid())

        self._refresh_job = None
        self._status_job = None
        self._adversary_job = None

        self._startup_loaded = False
        self._services_loaded = False

        self._prev_disk = None
        self._prev_time = None

        self.frame = None
        self.tree = None
        self.detail_text = None
        self.status_var = None
        self.search_var = None
        self.tree_mode_var = None
        self.startup_tree = None
        self.service_tree = None

    def build(self, parent):
        self.frame = parent

        toolbar = tk.Frame(parent)
        toolbar.pack(fill=tk.X, padx=6, pady=(6, 0))

        tk.Button(toolbar, text="← 返回主界面", width=12,
                  font=("Microsoft YaHei", 10),
                  command=self.app.show_home).pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(toolbar, text="任务管理器",
                 font=("Microsoft YaHei", 12, "bold")).pack(side=tk.LEFT)

        notebook = ttk.Notebook(parent)
        notebook.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self._build_process_tab(notebook)
        self._build_startup_tab(notebook)
        self._build_service_tab(notebook)

        self.status_var = tk.StringVar(value="就绪")
        status_bar = tk.Label(parent, textvariable=self.status_var, anchor="w",
                              font=("Microsoft YaHei", 9),
                              relief=tk.SUNKEN, bd=1)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        self._update_headings()
        self._warmup_cpu()
        self.refresh_processes()
        self._update_status()

    def _build_process_tab(self, notebook):
        tab = tk.Frame(notebook)
        notebook.add(tab, text="  进程  ")

        search_frame = tk.Frame(tab)
        search_frame.pack(fill=tk.X, padx=6, pady=(6, 0))

        tk.Label(search_frame, text="搜索:",
                 font=("Microsoft YaHei", 10)).pack(side=tk.LEFT)

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._on_search_change)
        tk.Entry(search_frame, textvariable=self.search_var,
                 font=("Microsoft YaHei", 10)
                 ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        tk.Button(search_frame, text="清除", width=6,
                  command=lambda: self.search_var.set("")
                  ).pack(side=tk.LEFT)

        self.tree_mode_var = tk.BooleanVar(value=False)
        tk.Checkbutton(search_frame, text="树形视图",
                       variable=self.tree_mode_var,
                       command=self._on_tree_mode_toggle
                       ).pack(side=tk.LEFT, padx=(8, 0))

        paned = tk.PanedWindow(tab, orient=tk.HORIZONTAL, sashwidth=5)
        paned.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        tree_frame = tk.Frame(paned)
        paned.add(tree_frame, stretch="always")

        self.tree = ttk.Treeview(tree_frame, columns=COLUMNS,
                                 show="tree headings",
                                 selectmode="extended")
        for col in COLUMNS:
            self.tree.heading(col, text=col)
        self.tree.column("#0", width=0, stretch=False)
        self.tree.column("pid", width=70, anchor="center")
        self.tree.column("name", width=280, anchor="w")
        self.tree.column("cpu", width=65, anchor="e")
        self.tree.column("memory", width=90, anchor="e")
        self.tree.column("status", width=70, anchor="center")
        self.tree.column("username", width=150, anchor="w")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        detail_frame = tk.LabelFrame(paned, text="详情", width=320)
        paned.add(detail_frame, stretch="never")

        self.detail_text = tk.Text(detail_frame, width=42, wrap="word",
                                   font=("Consolas", 9), state="disabled")
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        btn_frame = tk.Frame(tab)
        btn_frame.pack(fill=tk.X, padx=6, pady=(0, 6))

        tk.Button(btn_frame, text="刷新", width=10,
                  command=self.refresh_processes
                  ).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="结束进程", width=10,
                  command=self.kill_selected
                  ).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="强制结束", width=10,
                  command=lambda: self.kill_selected(force=True)
                  ).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="退出程序", width=10,
                  font=("Microsoft YaHei", 12, "bold"),
                  command=self.app.quit_all).pack(side=tk.RIGHT, padx=4)

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Button-3>", self._show_context_menu)

    def _build_startup_tab(self, notebook):
        tab = tk.Frame(notebook)
        notebook.add(tab, text="  启动项  ")

        self.startup_tree = ttk.Treeview(
            tab, columns=("name", "command", "location", "user"),
            show="headings")
        for c, t, w in [("name", "名称", 200), ("command", "命令", 400),
                        ("location", "位置", 180), ("user", "用户", 150)]:
            self.startup_tree.heading(c, text=t)
            self.startup_tree.column(c, width=w, anchor="w")
        self.startup_tree.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        vsb = ttk.Scrollbar(self.startup_tree, orient="vertical",
                            command=self.startup_tree.yview)
        self.startup_tree.configure(yscrollcommand=vsb.set)

        tk.Button(tab, text="刷新启动项", width=12,
                  command=lambda: threading.Thread(
                      target=self._load_startup_items, daemon=True).start()
                  ).pack(side=tk.LEFT, padx=6, pady=(0, 6))

    def _build_service_tab(self, notebook):
        tab = tk.Frame(notebook)
        notebook.add(tab, text="  服务  ")

        self.service_tree = ttk.Treeview(
            tab, columns=("name", "display", "status", "start"),
            show="headings")
        for c, t, w in [("name", "服务名", 200), ("display", "显示名", 320),
                        ("status", "状态", 100), ("start", "启动类型", 120)]:
            self.service_tree.heading(c, text=t)
            self.service_tree.column(c, width=w, anchor="w")
        self.service_tree.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        tk.Button(tab, text="刷新服务", width=12,
                  command=lambda: threading.Thread(
                      target=self._load_services, daemon=True).start()
                  ).pack(side=tk.LEFT, padx=6, pady=(0, 6))

    def on_show(self):
        super().on_show()
        self._schedule_refresh()
        self._schedule_status()
        self._schedule_adversary()

        if not self._startup_loaded:
            self._startup_loaded = True
            threading.Thread(target=self._load_startup_items,
                             daemon=True).start()
        if not self._services_loaded:
            self._services_loaded = True
            threading.Thread(target=self._load_services,
                             daemon=True).start()

    def on_hide(self):
        super().on_hide()
        for attr in ("_refresh_job", "_status_job", "_adversary_job"):
            job = getattr(self, attr, None)
            if job is not None:
                try:
                    self.app.root.after_cancel(job)
                except Exception:
                    pass
                setattr(self, attr, None)

    def _on_search_change(self, *_):
        self.search_keyword = self.search_var.get().strip().lower()
        self.refresh_processes()

    def _on_tree_mode_toggle(self):
        self.tree_mode = self.tree_mode_var.get()
        self.refresh_processes()

    def _sort_key(self):
        return {
            "pid": lambda p: p["pid"],
            "name": lambda p: p["name"].lower(),
            "cpu": lambda p: p["cpu"],
            "memory": lambda p: p["memory"],
            "status": lambda p: p["status"],
            "username": lambda p: p["username"].lower(),
        }.get(self.sort_column, lambda p: p["memory"])

    def _update_headings(self):
        arrow = " ▼" if self.sort_reverse else " ▲"
        labels = {"pid": "PID", "name": "进程名称", "cpu": "CPU %",
                  "memory": "内存 (MB)", "status": "状态", "username": "用户"}
        for col in COLUMNS:
            text = labels[col] + (arrow if col == self.sort_column else "")
            self.tree.heading(
                col, text=text,
                command=lambda c=col: self._on_heading_click(c))

    def _on_heading_click(self, col):
        if self.sort_column == col:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = col
            self.sort_reverse = col in ("memory", "cpu", "pid")
        self._update_headings()
        self.refresh_processes()

    def _warmup_cpu(self):
        psutil.cpu_percent(interval=None)
        for p in psutil.process_iter(["pid"]):
            try:
                psutil.Process(p.info["pid"]).cpu_percent(interval=None)
            except Exception:
                pass

    def _collect_processes(self):
        procs = []
        seen = set()

        for pid in psutil.pids():
            seen.add(pid)
            try:
                p = self._process_objects.get(pid)
                is_new = p is None
                if is_new:
                    p = psutil.Process(pid)
                    self._process_objects[pid] = p

                with p.oneshot():
                    mi = p.memory_info()
                    mem = mi.rss / 1024 / 1024 if mi else 0.0
                    info = {
                        "pid": pid,
                        "ppid": p.ppid(),
                        "name": p.name() or "未知",
                        "memory": mem,
                        "cpu": p.cpu_percent(interval=None),
                        "status": p.status(),
                        "username": self._username_cache.get(pid, ""),
                        "create_time": p.create_time(),
                    }

                if is_new and pid not in self._username_cache:
                    try:
                        uname = p.username() or ""
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        uname = ""
                    self._username_cache[pid] = uname
                    info["username"] = uname

                procs.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied,
                    psutil.ZombieProcess):
                self._process_objects.pop(pid, None)
                self._username_cache.pop(pid, None)

        for pid in list(self._process_objects.keys()):
            if pid not in seen:
                self._process_objects.pop(pid, None)
                self._username_cache.pop(pid, None)

        return procs

    def _format_row(self, p):
        return (
            p["pid"],
            p["name"],
            f"{p['cpu']:.1f}",
            _format_mem(p["memory"]),
            _STATUS_MAP.get(p["status"], p["status"]),
            p["username"],
        )

    @staticmethod
    def _match_keyword(pid, name, keyword):
        if not keyword:
            return True
        if keyword.isdigit() and keyword in str(pid):
            return True
        if keyword in (name or "").lower():
            return True
        return False

    def refresh_processes(self):
        if common.quitting or not self._visible:
            return
        if self.tree is None:
            return

        selected = set(self.tree.selection())
        expanded = set()
        if self.tree_mode:
            for iid in self.tree.get_children(""):
                if self.tree.item(iid, "open"):
                    expanded.add(iid)

        for item in self.tree.get_children(""):
            self.tree.delete(item)

        all_procs = self._collect_processes()
        keyword = self.search_keyword
        filtered = [p for p in all_procs
                    if self._match_keyword(p["pid"], p["name"], keyword)]
        filtered.sort(key=self._sort_key(), reverse=self.sort_reverse)

        if self.tree_mode:
            self._render_tree(filtered)
        else:
            self._render_flat(filtered)

        for iid in selected:
            if self.tree.exists(iid):
                self.tree.selection_add(iid)
        for iid in expanded:
            if self.tree.exists(iid):
                self.tree.item(iid, open=True)

        if selected:
            self._update_details(list(selected)[0])

    def _render_flat(self, procs):
        for p in procs:
            self.tree.insert("", tk.END, iid=str(p["pid"]),
                             values=self._format_row(p))

    def _render_tree(self, procs):
        by_pid = {p["pid"]: p for p in procs}
        children = {}
        roots = []
        for p in procs:
            ppid = p["ppid"]
            if ppid in by_pid and ppid != p["pid"]:
                children.setdefault(ppid, []).append(p)
            else:
                roots.append(p)

        key = self._sort_key()
        for lst in children.values():
            lst.sort(key=key, reverse=self.sort_reverse)
        roots.sort(key=key, reverse=self.sort_reverse)

        def add(parent_iid, proc):
            iid = str(proc["pid"])
            self.tree.insert(parent_iid, tk.END, iid=iid, text="",
                             values=self._format_row(proc), open=False)
            for c in children.get(proc["pid"], []):
                add(iid, c)

        for r in roots:
            add("", r)

    def _schedule_refresh(self):
        if self._refresh_job is not None:
            try:
                self.app.root.after_cancel(self._refresh_job)
            except Exception:
                pass
            self._refresh_job = None
        if not common.quitting and self._visible:
            self._refresh_job = self.app.root.after(4000, self._tick)

    def _tick(self):
        self._refresh_job = None
        if common.quitting or not self._visible:
            return
        self.refresh_processes()
        if not common.quitting and self._visible:
            self._refresh_job = self.app.root.after(4000, self._tick)

    def _schedule_status(self):
        if self._status_job is not None:
            try:
                self.app.root.after_cancel(self._status_job)
            except Exception:
                pass
            self._status_job = None
        if not common.quitting and self._visible:
            self._status_job = self.app.root.after(1000, self._update_status)

    def _update_status(self):
        self._status_job = None
        if common.quitting or not self._visible:
            return
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            used_gb = (mem.total - mem.available) / 1024 ** 3
            total_gb = mem.total / 1024 ** 3

            disk_str = ""
            try:
                d = psutil.disk_io_counters()
                now = time.time()
                if self._prev_disk and self._prev_time:
                    dt = now - self._prev_time
                    if dt > 0:
                        r = (d.read_bytes - self._prev_disk.read_bytes) / 1024 / 1024 / dt
                        w = (d.write_bytes - self._prev_disk.write_bytes) / 1024 / 1024 / dt
                        disk_str = f" | 磁盘 R:{r:.1f} W:{w:.1f} MB/s"
                self._prev_disk = d
                self._prev_time = now
            except Exception:
                pass

            me_mem = self._me.memory_info().rss / 1024 / 1024
            self.status_var.set(
                f"CPU {cpu:.1f}%  |  内存 {used_gb:.2f}/{total_gb:.2f} GB "
                f"({mem.percent:.0f}%){disk_str}  |  本进程 {me_mem:.1f} MB"
            )
        except Exception:
            pass
        if not common.quitting and self._visible:
            self._status_job = self.app.root.after(1000, self._update_status)

    def _schedule_adversary(self):
        if self._adversary_job is not None:
            try:
                self.app.root.after_cancel(self._adversary_job)
            except Exception:
                pass
            self._adversary_job = None
        if not common.quitting and self._visible:
            self._adversary_job = self.app.root.after(5000, self._check_adversary_tools)

    def _check_adversary_tools(self):
        self._adversary_job = None
        if common.quitting or not self._visible:
            return
        try:
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    name = (proc.info["name"] or "").lower()
                    if name in ADVERSARY_TOOLS:
                        key = (proc.info["pid"], name)
                        if key not in self._detected_tools:
                            self._detected_tools.add(key)
                            logger.warning(
                                f"检测到对抗工具: {name} "
                                f"(PID {proc.info['pid']})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass
        if not common.quitting and self._visible:
            self._adversary_job = self.app.root.after(5000, self._check_adversary_tools)

    def _on_tree_select(self, _event=None):
        sel = self.tree.selection()
        if sel:
            self._update_details(sel[0])

    def _update_details(self, pid_str):
        try:
            pid = int(pid_str)
        except (ValueError, TypeError):
            return

        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", tk.END)

        try:
            p = psutil.Process(pid)
            with p.oneshot():
                info = [
                    ("PID", pid),
                    ("父进程 PID", p.ppid()),
                    ("名称", p.name()),
                    ("状态", _STATUS_MAP.get(p.status(), p.status())),
                ]
                try:
                    info.append(("可执行文件", p.exe() or ""))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    info.append(("可执行文件", "(拒绝访问)"))
                try:
                    info.append(("命令行", " ".join(p.cmdline())))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    info.append(("命令行", "(拒绝访问)"))
                try:
                    info.append(("工作目录", p.cwd()))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    info.append(("工作目录", "(拒绝访问)"))
                try:
                    info.append(("用户名", p.username()))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    info.append(("用户名", "(拒绝访问)"))

                ct = p.create_time()
                info.append(("启动时间", datetime.datetime
                             .fromtimestamp(ct)
                             .strftime("%Y-%m-%d %H:%M:%S")))
                info.append(("已运行", str(datetime.timedelta(
                    seconds=int(time.time() - ct)))))
                mi = p.memory_info()
                if mi:
                    info.append(("内存 RSS", f"{mi.rss / 1024 / 1024:.1f} MB"))
                    info.append(("内存 VMS", f"{mi.vms / 1024 / 1024:.1f} MB"))
                info.append(("线程数", p.num_threads()))
                try:
                    info.append(("句柄数", p.num_handles()))
                except (psutil.AccessDenied, AttributeError):
                    pass
                info.append(("CPU %", f"{p.cpu_percent(interval=None):.1f}"))

            for k, v in info:
                self.detail_text.insert(tk.END, f"{k}:\n", "key")
                self.detail_text.insert(tk.END, f"  {v}\n\n")
            self.detail_text.tag_configure(
                "key", foreground="#2d6cdf",
                font=("Microsoft YaHei", 9, "bold"))
        except psutil.NoSuchProcess:
            self.detail_text.insert(tk.END, "进程已不存在")
        except psutil.AccessDenied:
            self.detail_text.insert(tk.END, "拒绝访问")
        except Exception as e:
            self.detail_text.insert(tk.END, f"读取失败: {e}")

        self.detail_text.configure(state="disabled")

    def kill_selected(self, force=False):
        selected = list(self.tree.selection())
        if not selected:
            common.toast("请先选择一个或多个进程", "warn")
            return

        guard_pid = None
        d = read_json(GUARD_PID)
        if d:
            guard_pid = d.get("guard_pid")

        my_pid = os.getpid()
        targets = []
        skipped = []

        for iid in selected:
            try:
                pid = int(iid)
            except ValueError:
                continue
            if pid == my_pid:
                skipped.append(f"{pid} (自己)")
                continue
            if guard_pid and pid == guard_pid:
                skipped.append(f"{pid} (守护进程)")
                continue
            try:
                name = psutil.Process(pid).name()
            except Exception:
                name = "未知"
            targets.append((pid, name))

        if not targets:
            common.toast("没有可结束的进程：" + ", ".join(skipped), "warn")
            return

        ok, fail = 0, []
        for pid, name in targets:
            try:
                p = psutil.Process(pid)
                if force:
                    p.kill()
                else:
                    p.terminate()
                    try:
                        p.wait(timeout=3)
                    except psutil.TimeoutExpired:
                        p.kill()
                ok += 1
                logger.info(f"已结束进程 {name} (PID {pid})"
                            f"{' [强制]' if force else ''}")
            except Exception as e:
                fail.append(f"{name}({pid}): {e}")
                logger.error(f"结束进程 {name} (PID {pid}) 失败: {e}")

        msg = f"成功结束 {ok} 个进程"
        if fail:
            msg += f"（失败 {len(fail)}）"
        if skipped:
            msg += f"（跳过 {len(skipped)}）"
        common.toast(msg, "success" if ok else "warn")
        self.refresh_processes()

    def _open_file_location(self):
        sel = self.tree.selection()
        if not sel:
            return
        try:
            p = psutil.Process(int(sel[0]))
            exe = p.exe()
            if exe and os.path.exists(exe):
                subprocess.Popen(["explorer", "/select,", exe])
            else:
                common.toast("无法定位可执行文件", "warn")
        except Exception as e:
            common.toast(f"无法打开: {e}", "error")

    def _copy_to_clipboard(self, text):
        try:
            self.app.root.clipboard_clear()
            self.app.root.clipboard_append(text)
            self.app.root.update()
        except Exception:
            pass

    def _copy_pid(self):
        sel = self.tree.selection()
        if sel:
            self._copy_to_clipboard("\n".join(sel))

    def _copy_path(self):
        sel = self.tree.selection()
        if not sel:
            return
        try:
            exe = psutil.Process(int(sel[0])).exe()
            self._copy_to_clipboard(exe or "")
        except Exception:
            pass

    def _open_vt(self):
        sel = self.tree.selection()
        if not sel:
            return
        try:
            pid = int(sel[0])
            name = psutil.Process(pid).name()
        except Exception:
            name = "未知"
        url = f"https://www.virustotal.com/gui/search/{name}"
        self.app.open_in_browser(url)
        logger.info(f"任务管理器: 打开 VT 查询 {name}")

    def _show_context_menu(self, event):
        row = self.tree.identify_row(event.y)
        if row and row not in self.tree.selection():
            self.tree.selection_set(row)
        menu = tk.Menu(self.app.root, tearoff=0)
        menu.add_command(label="结束进程", command=self.kill_selected)
        menu.add_command(label="强制结束",
                         command=lambda: self.kill_selected(force=True))
        menu.add_separator()
        menu.add_command(label="打开文件所在位置",
                         command=self._open_file_location)
        menu.add_separator()
        menu.add_command(label="复制 PID", command=self._copy_pid)
        menu.add_command(label="复制路径", command=self._copy_path)
        menu.add_separator()
        menu.add_command(label="在隔离浏览器中查 VirusTotal",
                         command=self._open_vt)
        menu.add_separator()
        menu.add_command(label="刷新", command=self.refresh_processes)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _load_startup_items(self):
        try:
            out = _run_ps(
                "Get-CimInstance Win32_StartupCommand | "
                "Select-Object Name,Command,Location,User | "
                "ConvertTo-Json -Compress")
            data = json.loads(out) if out.strip() else []
            if isinstance(data, dict):
                data = [data]
            self.app.root.after(0, self._fill_startup, data)
        except Exception as e:
            logger.error(f"读取启动项失败: {e}")
            self.app.root.after(
                0, lambda: common.toast(f"读取启动项失败: {e}", "error"))

    def _fill_startup(self, data):
        for item in self.startup_tree.get_children():
            self.startup_tree.delete(item)
        for it in data:
            self.startup_tree.insert("", tk.END, values=(
                it.get("Name", ""),
                it.get("Command", ""),
                it.get("Location", ""),
                it.get("User", "") or "",
            ))
        logger.info(f"已加载 {len(data)} 条启动项")
        if self.status_var:
            self.status_var.set(f"启动项已加载: {len(data)} 条")

    def _load_services(self):
        try:
            out = _run_ps(
                "Get-Service | Select-Object Name,DisplayName,Status,StartType | "
                "ConvertTo-Json -Compress")
            data = json.loads(out) if out.strip() else []
            if isinstance(data, dict):
                data = [data]
            self.app.root.after(0, self._fill_services, data)
        except Exception as e:
            logger.error(f"读取服务失败: {e}")
            self.app.root.after(
                0, lambda: common.toast(f"读取服务失败: {e}", "error"))

    def _fill_services(self, data):
        status_map = {"Running": "运行中", "Stopped": "已停止",
                      "Paused": "已暂停", "StartPending": "启动中",
                      "StopPending": "停止中"}
        for item in self.service_tree.get_children():
            self.service_tree.delete(item)
        for it in data:
            self.service_tree.insert("", tk.END, values=(
                it.get("Name", ""),
                it.get("DisplayName", ""),
                status_map.get(str(it.get("Status", "")),
                               str(it.get("Status", ""))),
                str(it.get("StartType", "")),
            ))
        logger.info(f"已加载 {len(data)} 个服务")
        if self.status_var:
            self.status_var.set(f"服务已加载: {len(data)} 个")