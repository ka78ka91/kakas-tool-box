import tkinter as tk
from tkinter import ttk
import os

import common
from common import logger, LOG_FILE
from tool import Tool


class LogViewerTool(Tool):
    name = "log_viewer"
    display_name = "日志查看"
    description = "查看工具箱的运行日志"
    icon = "📜"

    def __init__(self, app):
        super().__init__(app)
        self._all_lines = []
        self._filter_level = "全部"
        self._filter_keyword = ""

        self.frame = None
        self.text = None
        self.status_var = None
        self.level_var = None
        self.kw_var = None

    def build(self, parent):
        self.frame = parent

        toolbar = tk.Frame(parent)
        toolbar.pack(fill=tk.X, padx=6, pady=(6, 0))

        tk.Button(toolbar, text="← 返回主界面", width=12,
                  font=("Microsoft YaHei", 10),
                  command=self.app.show_home).pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(toolbar, text="日志查看",
                 font=("Microsoft YaHei", 12, "bold")).pack(side=tk.LEFT)

        tk.Button(toolbar, text="刷新", width=8,
                  command=self.reload).pack(side=tk.LEFT, padx=(20, 4))
        tk.Button(toolbar, text="清空日志", width=10,
                  command=self.clear_log).pack(side=tk.LEFT, padx=4)
        tk.Button(toolbar, text="打开所在目录", width=12,
                  command=self.open_dir).pack(side=tk.LEFT, padx=4)

        tk.Button(toolbar, text="退出程序", width=10,
                  font=("Microsoft YaHei", 12, "bold"),
                  command=self.app.quit_all).pack(side=tk.RIGHT, padx=4)

        filter_frame = tk.Frame(parent)
        filter_frame.pack(fill=tk.X, padx=6, pady=(6, 0))

        tk.Label(filter_frame, text="级别:",
                 font=("Microsoft YaHei", 10)).pack(side=tk.LEFT)
        self.level_var = tk.StringVar(value="全部")
        level_combo = ttk.Combobox(
            filter_frame, textvariable=self.level_var,
            values=["全部", "INFO", "WARNING", "ERROR"],
            state="readonly", width=10)
        level_combo.pack(side=tk.LEFT, padx=(4, 16))
        level_combo.bind("<<ComboboxSelected>>", lambda e: self._render())

        tk.Label(filter_frame, text="关键词:",
                 font=("Microsoft YaHei", 10)).pack(side=tk.LEFT)
        self.kw_var = tk.StringVar()
        self.kw_var.trace_add("write", lambda *a: self._render())
        tk.Entry(filter_frame, textvariable=self.kw_var,
                 font=("Microsoft YaHei", 10), width=30
                 ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)

        text_frame = tk.Frame(parent)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self.text = tk.Text(text_frame, wrap="none",
                            font=("Consolas", 9), state="disabled")
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        vsb = ttk.Scrollbar(text_frame, orient="vertical",
                            command=self.text.yview)
        self.text.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.text.tag_configure("INFO", foreground="#1a7f37")
        self.text.tag_configure("WARNING", foreground="#8a6d3b")
        self.text.tag_configure("ERROR", foreground="#a11")

        self.status_var = tk.StringVar(value="就绪")
        tk.Label(parent, textvariable=self.status_var, anchor="w",
                 font=("Microsoft YaHei", 9),
                 relief=tk.SUNKEN, bd=1).pack(fill=tk.X, side=tk.BOTTOM)

    def on_show(self):
        super().on_show()
        self.reload()

    def reload(self):
        self._all_lines = []
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r", encoding="utf-8",
                          errors="replace") as f:
                    self._all_lines = f.readlines()
        except Exception as e:
            logger.error(f"读取日志失败: {e}")
        self._render()

    def _render(self):
        self._filter_level = self.level_var.get()
        self._filter_keyword = self.kw_var.get().strip().lower()

        self.text.configure(state="normal")
        self.text.delete("1.0", tk.END)

        shown = 0
        for line in self._all_lines:
            if self._filter_level != "全部":
                if f"[{self._filter_level}]" not in line:
                    continue
            if self._filter_keyword and self._filter_keyword not in line.lower():
                continue
            tag = ""
            if "[INFO]" in line:
                tag = "INFO"
            elif "[WARNING]" in line:
                tag = "WARNING"
            elif "[ERROR]" in line:
                tag = "ERROR"
            self.text.insert(tk.END, line, tag)
            shown += 1

        self.text.configure(state="disabled")
        self.text.see(tk.END)
        self.status_var.set(
            f"共 {len(self._all_lines)} 行，显示 {shown} 行")

    def clear_log(self):
        try:
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                f.write("")
            logger.info("日志已清空")
            common.toast("日志已清空", "success")
        except Exception as e:
            common.toast(f"清空失败: {e}", "error")
        self.reload()

    def open_dir(self):
        try:
            os.startfile(os.path.dirname(LOG_FILE))
        except Exception as e:
            common.toast(f"无法打开: {e}", "error")