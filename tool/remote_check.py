import tkinter as tk
from tkinter import ttk, filedialog
import os
import sys
import re
import json
import time
import ctypes
import subprocess
import threading
import datetime
import psutil

import common
from common import logger, CREATE_NO_WINDOW
from tool import Tool


REMOTE_TOOLS = {
    "teamviewer.exe": "TeamViewer",
    "teamviewer_service.exe": "TeamViewer 服务",
    "tv_w32.exe": "TeamViewer",
    "tv_x64.exe": "TeamViewer",
    "sunloginclient.exe": "向日葵",
    "sunlogin_service.exe": "向日葵服务",
    "awesun.exe": "向日葵国际版",
    "awesunclient.exe": "向日葵国际版",
    "todesk.exe": "ToDesk",
    "todesk_service.exe": "ToDesk 服务",
    "anydesk.exe": "AnyDesk",
    "rustdesk.exe": "RustDesk",
    "winvnc.exe": "VNC Server",
    "vncserver.exe": "VNC Server",
    "tvnserver.exe": "TightVNC",
    "uvnc_service.exe": "UltraVNC",
    "radmin.exe": "Radmin",
    "rserver3.exe": "Radmin Server",
    "mstsc.exe": "远程桌面客户端",
    "gotohttp.exe": "GoToMyPC",
    "gotomypc.exe": "GoToMyPC",
    "aa_v3.exe": "Ammyy Admin",
    "netsupport.exe": "NetSupport",
}

SUSPICIOUS_PORTS = {
    4444, 5555, 1337, 31337, 6666, 6667, 8888,
    9001, 9030, 1080, 8081, 12345, 54321,
}

HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"

_HOSTS_WHITELIST_PATTERNS = [
    r"^127\.0\.0\.1\s+localhost",
    r"^::1\s+localhost",
    r"^0\.0\.0\.0\s+0\.0\.0\.0",
    r"^#",
    r"^\s*$",
]


def check_remote_processes():
    found = []
    for p in psutil.process_iter(["pid", "name", "exe", "username"]):
        try:
            name = (p.info["name"] or "").lower()
            if name in REMOTE_TOOLS:
                found.append({
                    "pid": p.info["pid"],
                    "name": p.info["name"],
                    "label": REMOTE_TOOLS[name],
                    "exe": p.info.get("exe") or "",
                    "username": p.info.get("username") or "",
                    "action": "kill_process",
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return found


def check_rdp():
    issues = []
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"System\CurrentControlSet\Control\Terminal Server")
        try:
            val, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
            if val == 0:
                issues.append({
                    "name": "远程桌面 (RDP)",
                    "detail": "已开启（fDenyTSConnections=0）",
                    "action": "disable_rdp",
                })
        except FileNotFoundError:
            pass
        winreg.CloseKey(key)
    except Exception as e:
        logger.error(f"检查 RDP 失败: {e}")
    return issues


def check_remote_assistance():
    issues = []
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"System\CurrentControlSet\Control\Remote Assistance")
        try:
            val, _ = winreg.QueryValueEx(key, "fAllowToGetHelp")
            if val == 1:
                issues.append({
                    "name": "远程协助",
                    "detail": "已开启（fAllowToGetHelp=1）",
                    "action": "disable_assistance",
                })
        except FileNotFoundError:
            pass
        winreg.CloseKey(key)
    except Exception as e:
        logger.error(f"检查远程协助失败: {e}")
    return issues


def check_rdp_sessions():
    issues = []
    try:
        r = subprocess.run(
            ["qwinsta"], capture_output=True, timeout=5,
            creationflags=CREATE_NO_WINDOW)
        out = r.stdout.decode("gbk", errors="replace")
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            if (line.lower().startswith("sessionname")
                    or line.startswith("服务")
                    or line.startswith("SESSIONNAME")):
                continue
            parts = line.split()
            if len(parts) >= 3:
                if "rdp" in parts[0].lower():
                    state = parts[2] if len(parts) > 2 else "未知"
                    if state.lower() in ("active", "活动"):
                        issues.append({
                            "name": "活动 RDP 会话",
                            "detail": line,
                            "action": "manual",
                        })
    except Exception as e:
        logger.error(f"检查 RDP 会话失败: {e}")
    return issues


def check_network_connections():
    issues = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            try:
                laddr = conn.laddr
                raddr = conn.raddr
                pid = conn.pid
                status = conn.status

                if status == "LISTEN" and laddr and laddr.port in SUSPICIOUS_PORTS:
                    proc_name = ""
                    if pid:
                        try:
                            proc_name = psutil.Process(pid).name()
                        except Exception:
                            pass
                    issues.append({
                        "name": "可疑监听端口",
                        "detail": f"端口 {laddr.port} 被 "
                                  f"{proc_name or 'PID ' + str(pid)} 监听",
                        "pid": pid,
                        "action": "kill_process" if pid else "manual",
                    })

                if (status == "ESTABLISHED" and raddr
                        and raddr.ip not in ("127.0.0.1", "::1")
                        and not raddr.ip.startswith("192.168.")
                        and not raddr.ip.startswith("10.")
                        and not raddr.ip.startswith("172.")):
                    if raddr.port in SUSPICIOUS_PORTS:
                        proc_name = ""
                        if pid:
                            try:
                                proc_name = psutil.Process(pid).name()
                            except Exception:
                                pass
                        issues.append({
                            "name": "可疑外网连接",
                            "detail": f"{raddr.ip}:{raddr.port} ← "
                                      f"{proc_name or 'PID ' + str(pid)}",
                            "pid": pid,
                            "action": "manual",
                        })
            except Exception:
                pass
    except Exception as e:
        logger.error(f"检查网络连接失败: {e}")
    return issues


def check_hosts():
    issues = []
    try:
        if not os.path.exists(HOSTS_PATH):
            return issues
        with open(HOSTS_PATH, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        suspicious = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                continue
            clean = stripped.lstrip("\ufeff\u200b")
            is_whitelisted = False
            for pat in _HOSTS_WHITELIST_PATTERNS:
                if re.match(pat, clean):
                    is_whitelisted = True
                    break
            if not is_whitelisted:
                parts = clean.split()
                if len(parts) >= 2:
                    suspicious.append(f"第 {i} 行: {clean}")
        if suspicious:
            issues.append({
                "name": "hosts 文件",
                "detail": f"发现 {len(suspicious)} 条非默认记录",
                "extra": suspicious[:5],
                "action": "open_hosts",
            })
    except Exception as e:
        logger.error(f"检查 hosts 失败: {e}")
    return issues


def check_startup_remote():
    issues = []
    try:
        import winreg
        keys = [
            (winreg.HKEY_CURRENT_USER,
             r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ]
        for hive, path in keys:
            try:
                key = winreg.OpenKey(hive, path)
            except FileNotFoundError:
                continue
            try:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        i += 1
                        low = (value or "").lower()
                        for tool_key in REMOTE_TOOLS:
                            if tool_key in low:
                                issues.append({
                                    "name": "启动项",
                                    "detail": f"{name} = {value}",
                                    "action": "manual",
                                })
                                break
                    except OSError:
                        break
            finally:
                winreg.CloseKey(key)
    except Exception as e:
        logger.error(f"检查启动项失败: {e}")
    return issues


def check_services_remote():
    issues = []
    try:
        for svc in psutil.win_service_iter():
            try:
                info = svc.as_dict()
                name = (info.get("name") or "").lower()
                display = (info.get("display_name") or "").lower()
                binpath = (info.get("binpath") or "").lower()
                for tool_key in REMOTE_TOOLS:
                    if (tool_key in binpath or tool_key in name
                            or "teamviewer" in display
                            or "向日葵" in display
                            or "todesk" in display
                            or "anydesk" in display):
                        issues.append({
                            "name": "服务",
                            "detail": f"{info.get('display_name')} "
                                      f"({info.get('name')}) - "
                                      f"{info.get('status')}",
                            "action": "manual",
                        })
                        break
            except Exception:
                pass
    except Exception as e:
        logger.error(f"检查服务失败: {e}")
    return issues


def fix_kill_process(pid):
    try:
        p = psutil.Process(pid)
        p.terminate()
        try:
            p.wait(timeout=3)
        except psutil.TimeoutExpired:
            p.kill()
        logger.info(f"远控检测: 已结束进程 PID {pid}")
        return True, ""
    except Exception as e:
        logger.error(f"结束进程 {pid} 失败: {e}")
        return False, str(e)


def fix_disable_rdp():
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"System\CurrentControlSet\Control\Terminal Server",
            0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "fDenyTSConnections", 0,
                          winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        logger.info("远控检测: 已关闭远程桌面")
        return True, ""
    except Exception as e:
        logger.error(f"关闭远程桌面失败: {e}")
        return False, str(e)


def fix_disable_assistance():
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"System\CurrentControlSet\Control\Remote Assistance",
            0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "fAllowToGetHelp", 0,
                          winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        logger.info("远控检测: 已关闭远程协助")
        return True, ""
    except Exception as e:
        logger.error(f"关闭远程协助失败: {e}")
        return False, str(e)


class RemoteCheckTool(Tool):
    name = "remote_check"
    display_name = "远控检测"
    description = "扫描远控软件、远程桌面、可疑连接与 hosts 改动"
    icon = "🛰️"

    def __init__(self, app):
        super().__init__(app)
        self._scanning = False
        self._results = []
        self._tree_items = {}

        self.frame = None
        self.tree = None
        self.status_var = None
        self.summary_label = None
        self.scan_btn = None

    def build(self, parent):
        self.frame = parent

        toolbar = tk.Frame(parent)
        toolbar.pack(fill=tk.X, padx=6, pady=(6, 0))

        tk.Button(toolbar, text="← 返回主界面", width=12,
                  font=("Microsoft YaHei", 10),
                  command=self.app.show_home).pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(toolbar, text="远控检测",
                 font=("Microsoft YaHei", 12, "bold")).pack(side=tk.LEFT)

        self.scan_btn = tk.Button(toolbar, text="重新检测", width=10,
                                  command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(20, 4))

        tk.Button(toolbar, text="退出程序", width=10,
                  font=("Microsoft YaHei", 12, "bold"),
                  command=self.app.quit_all).pack(side=tk.RIGHT, padx=4)

        self.summary_label = tk.Label(
            parent, text="点击「重新检测」开始扫描",
            font=("Microsoft YaHei", 11, "bold"),
            bg="#eef3ff", fg="#2d6cdf",
            anchor="w", padx=12, pady=10)
        self.summary_label.pack(fill=tk.X, padx=6, pady=(6, 0))

        list_frame = tk.Frame(parent)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        cols = ("status", "category", "detail", "action")
        self.tree = ttk.Treeview(list_frame, columns=cols,
                                 show="headings",
                                 selectmode="extended")
        for c, t, w, a in [
            ("status", "状态", 70, "center"),
            ("category", "类别", 140, "w"),
            ("detail", "详情", 480, "w"),
            ("action", "可操作", 100, "center"),
        ]:
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor=a)

        self.tree.tag_configure("ok", foreground="#1a7f37")
        self.tree.tag_configure("warn", background="#fff6dc",
                                foreground="#8a6d3b")
        self.tree.tag_configure("danger", background="#ffdede",
                                foreground="#a11")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        vsb = ttk.Scrollbar(list_frame, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<Button-3>", self._show_context_menu)

        btn_frame = tk.Frame(parent)
        btn_frame.pack(fill=tk.X, padx=6, pady=(0, 6))

        tk.Button(btn_frame, text="一键修复选中", width=14,
                  command=self.fix_selected).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="修复全部", width=10,
                  command=self.fix_all).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="导出报告", width=10,
                  command=self.export_report).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="打开 hosts", width=10,
                  command=self.open_hosts).pack(side=tk.LEFT, padx=4)

        self.status_var = tk.StringVar(value="就绪")
        tk.Label(parent, textvariable=self.status_var, anchor="w",
                 font=("Microsoft YaHei", 9),
                 relief=tk.SUNKEN, bd=1).pack(fill=tk.X, side=tk.BOTTOM)

    def on_show(self):
        super().on_show()
        if not self._results:
            self.app.root.after(150, self.start_scan)

    def on_hide(self):
        super().on_hide()
        self._scanning = False

    def start_scan(self):
        if self._scanning or not self._visible:
            return
        self._scanning = True
        self.scan_btn.configure(state="disabled", text="检测中…")
        self.summary_label.configure(text="正在检测，请稍候…",
                                     bg="#eef3ff", fg="#2d6cdf")
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._tree_items.clear()
        self._results.clear()

        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        results = []

        try:
            procs = check_remote_processes()
            if procs:
                for p in procs:
                    results.append({
                        "status": "danger",
                        "category": "远控软件进程",
                        "detail": f"{p['label']} - {p['name']} "
                                  f"(PID {p['pid']})",
                        "action": "kill_process",
                        "pid": p["pid"],
                    })
            else:
                results.append({
                    "status": "ok",
                    "category": "远控软件进程",
                    "detail": "无",
                    "action": "",
                })
        except Exception as e:
            logger.error(f"检测远控进程失败: {e}")

        try:
            rdp = check_rdp()
            if rdp:
                for r in rdp:
                    results.append({
                        "status": "warn",
                        "category": r["name"],
                        "detail": r["detail"],
                        "action": r["action"],
                    })
            else:
                results.append({
                    "status": "ok",
                    "category": "远程桌面 (RDP)",
                    "detail": "已关闭",
                    "action": "",
                })
        except Exception as e:
            logger.error(f"检测 RDP 失败: {e}")

        try:
            ra = check_remote_assistance()
            if ra:
                for r in ra:
                    results.append({
                        "status": "warn",
                        "category": r["name"],
                        "detail": r["detail"],
                        "action": r["action"],
                    })
            else:
                results.append({
                    "status": "ok",
                    "category": "远程协助",
                    "detail": "已关闭",
                    "action": "",
                })
        except Exception as e:
            logger.error(f"检测远程协助失败: {e}")

        try:
            sess = check_rdp_sessions()
            if sess:
                for r in sess:
                    results.append({
                        "status": "danger",
                        "category": r["name"],
                        "detail": r["detail"],
                        "action": "manual",
                    })
            else:
                results.append({
                    "status": "ok",
                    "category": "活动会话",
                    "detail": "无",
                    "action": "",
                })
        except Exception as e:
            logger.error(f"检测会话失败: {e}")

        try:
            net = check_network_connections()
            if net:
                for r in net:
                    results.append({
                        "status": "warn",
                        "category": r["name"],
                        "detail": r["detail"],
                        "action": r.get("action", "manual"),
                        "pid": r.get("pid"),
                    })
            else:
                results.append({
                    "status": "ok",
                    "category": "网络连接",
                    "detail": "无可疑连接",
                    "action": "",
                })
        except Exception as e:
            logger.error(f"检测网络连接失败: {e}")

        try:
            hosts = check_hosts()
            if hosts:
                for r in hosts:
                    detail = r["detail"]
                    if r.get("extra"):
                        detail += "  |  " + " / ".join(r["extra"])
                    results.append({
                        "status": "warn",
                        "category": r["name"],
                        "detail": detail,
                        "action": r.get("action", ""),
                    })
            else:
                results.append({
                    "status": "ok",
                    "category": "hosts 文件",
                    "detail": "正常",
                    "action": "",
                })
        except Exception as e:
            logger.error(f"检测 hosts 失败: {e}")

        try:
            startup = check_startup_remote()
            if startup:
                for r in startup:
                    results.append({
                        "status": "warn",
                        "category": r["name"],
                        "detail": r["detail"],
                        "action": "manual",
                    })
            else:
                results.append({
                    "status": "ok",
                    "category": "启动项",
                    "detail": "无远控相关",
                    "action": "",
                })
        except Exception as e:
            logger.error(f"检测启动项失败: {e}")

        try:
            svcs = check_services_remote()
            if svcs:
                for r in svcs:
                    results.append({
                        "status": "warn",
                        "category": r["name"],
                        "detail": r["detail"],
                        "action": "manual",
                    })
            else:
                results.append({
                    "status": "ok",
                    "category": "服务",
                    "detail": "无远控相关",
                    "action": "",
                })
        except Exception as e:
            logger.error(f"检测服务失败: {e}")

        self.app.root.after(0, lambda: self._apply_results(results))

    def _apply_results(self, results):
        self._scanning = False
        if not self._visible:
            return
        self._results = results

        try:
            self.scan_btn.configure(state="normal", text="重新检测")
        except Exception:
            return

        for i, r in enumerate(results):
            iid = f"r{i}"
            action_text = {
                "kill_process": "可结束",
                "disable_rdp": "可关闭",
                "disable_assistance": "可关闭",
                "open_hosts": "可查看",
                "manual": "手动",
                "": "—",
            }.get(r.get("action", ""), "—")
            self.tree.insert(
                "", tk.END, iid=iid,
                values=(self._status_text(r["status"]),
                        r["category"], r["detail"], action_text),
                tags=(r["status"],))
            self._tree_items[iid] = r

        n_danger = sum(1 for r in results if r["status"] == "danger")
        n_warn = sum(1 for r in results if r["status"] == "warn")

        if n_danger > 0:
            self.summary_label.configure(
                text=f"⚠ 发现 {n_danger} 项高危、{n_warn} 项警告，"
                     f"建议立即处理",
                bg="#ffdede", fg="#a11")
        elif n_warn > 0:
            self.summary_label.configure(
                text=f"⚠ 发现 {n_warn} 项警告，建议查看",
                bg="#fff6dc", fg="#8a6d3b")
        else:
            self.summary_label.configure(
                text="✅ 未发现远控迹象",
                bg="#e6f7ea", fg="#1a7f37")

        self.status_var.set(
            f"检测完成 — 高危 {n_danger} 项，警告 {n_warn} 项")
        logger.info(f"远控检测完成: 高危 {n_danger}, 警告 {n_warn}")

    @staticmethod
    def _status_text(s):
        return {"ok": "✅", "warn": "⚠", "danger": "🔴"}.get(s, "?")

    def fix_selected(self):
        sel = list(self.tree.selection())
        if not sel:
            common.toast("请先选择要修复的项目", "warn")
            return
        self._fix_items(sel)

    def fix_all(self):
        fixable = [iid for iid, r in self._tree_items.items()
                   if r.get("action") in
                   ("kill_process", "disable_rdp", "disable_assistance")]
        if not fixable:
            common.toast("没有可一键修复的项目", "warn")
            return
        common.toast(f"正在修复 {len(fixable)} 个项目…", "info")
        self._fix_items(fixable)

    def _fix_items(self, iids):
        ok, fail, skipped = 0, [], 0
        for iid in iids:
            r = self._tree_items.get(iid)
            if not r:
                continue
            action = r.get("action")
            if action == "kill_process" and r.get("pid"):
                success, err = fix_kill_process(r["pid"])
            elif action == "disable_rdp":
                success, err = fix_disable_rdp()
            elif action == "disable_assistance":
                success, err = fix_disable_assistance()
            else:
                skipped += 1
                continue
            if success:
                ok += 1
            else:
                fail.append(f"{r['category']}: {err}")

        msg = f"已修复 {ok} 项"
        if skipped:
            msg += f"（跳过 {skipped}）"
        if fail:
            msg += f"（失败 {len(fail)}）"
        common.toast(msg, "success" if ok else "warn")

        self.app.root.after(300, self.start_scan)

    def open_hosts(self):
        if os.path.exists(HOSTS_PATH):
            try:
                os.startfile(HOSTS_PATH)
            except Exception:
                subprocess.Popen(["notepad.exe", HOSTS_PATH])
        else:
            common.toast("hosts 文件不存在", "warn")

    def _on_double_click(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        r = self._tree_items.get(sel[0])
        if r and r.get("action") == "open_hosts":
            self.open_hosts()

    def _show_context_menu(self, event):
        row = self.tree.identify_row(event.y)
        if row and row not in self.tree.selection():
            self.tree.selection_set(row)

        r = self._tree_items.get(row)
        menu = tk.Menu(self.app.root, tearoff=0)
        added = False

        if r:
            detail = r.get("detail", "")
            cat = r.get("category", "")

            if "连接" in cat or "端口" in cat:
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", detail)
                if m:
                    ip = m.group(1)
                    menu.add_command(
                        label=f"在隔离浏览器中查 IP {ip}",
                        command=lambda u=f"https://ip.sb/?q={ip}":
                            self.app.open_in_browser(u))
                    added = True

            if r.get("action") == "open_hosts":
                menu.add_command(label="打开 hosts", command=self.open_hosts)
                added = True

        if not added:
            menu.add_command(label="刷新", command=self.start_scan)

        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def export_report(self):
        if not self._results:
            common.toast("请先检测", "warn")
            return
        path = filedialog.asksaveasfilename(
            title="保存检测报告",
            defaultextension=".json",
            initialfile=f"remote_check_"
                        f"{datetime.datetime.now():%Y%m%d_%H%M%S}.json",
            filetypes=[("JSON", "*.json"), ("所有文件", "*.*")])
        if not path:
            return
        report = {
            "time": datetime.datetime.now().isoformat(),
            "results": self._results,
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            common.toast(f"报告已保存到: {path}", "success")
        except Exception as e:
            common.toast(f"保存失败: {e}", "error")


def run_startup_check():
    try:
        procs = check_remote_processes()
        rdp = check_rdp()
        hosts = check_hosts()
        danger = len(procs)
        warn = len(rdp) + len(hosts)
        if danger == 0 and warn == 0:
            return 0, 0, "系统状态正常"
        parts = []
        if procs:
            parts.append(f"{len(procs)} 个远控软件在运行")
        if rdp:
            parts.append("远程桌面已开启")
        if hosts:
            parts.append("hosts 被修改")
        return danger, warn, "；".join(parts)
    except Exception as e:
        logger.error(f"启动自检失败: {e}")
        return 0, 0, ""