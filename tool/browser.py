import tkinter as tk
import os
import sys
import subprocess

import common
from common import logger, CREATE_NO_WINDOW
from tool import Tool

try:
    import webview  # noqa: F401
    HAS_WEBVIEW = True
except ImportError:
    HAS_WEBVIEW = False


_BROWSER_MAIN = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "_browser_main.py")
_BROWSER_PROC = None


def open_browser(url="about:blank"):
    global _BROWSER_PROC

    if not HAS_WEBVIEW:
        common.toast("未安装 pywebview，请执行 pip install pywebview",
                     "error", 5000)
        return

    if _BROWSER_PROC is not None:
        try:
            if _BROWSER_PROC.poll() is None:
                logger.info("隔离浏览器已在运行，忽略重复打开请求")
                return
        except Exception:
            pass

    try:
        # 打包后：用 exe 自己启动，加特殊参数进入浏览器模式
        if getattr(sys, "frozen", False):
            # exe 启动，--browser 参数让 main.py 走浏览器分支
            proc = subprocess.Popen(
                [sys.executable, "--browser", url],
                creationflags=CREATE_NO_WINDOW)
        else:
            # 源码运行：直接调 _browser_main.py
            proc = subprocess.Popen(
                [sys.executable, _BROWSER_MAIN, url],
                creationflags=CREATE_NO_WINDOW)
        _BROWSER_PROC = proc
        logger.info(f"隔离浏览器已启动: {url}")
    except Exception as e:
        logger.error(f"启动隔离浏览器失败: {e}")
        common.toast(f"启动失败: {e}", "error")


class BrowserTool(Tool):
    name = "browser"
    display_name = "隔离浏览器"
    description = "打开可疑链接的安全窗口（独立 Cookie、无痕）"
    icon = "🌐"

    def __init__(self, app):
        super().__init__(app)
        self.frame = None
        self.url_var = None
        self.status_var = None

    def build(self, parent):
        self.frame = parent

        toolbar = tk.Frame(parent)
        toolbar.pack(fill=tk.X, padx=6, pady=(6, 0))

        tk.Button(toolbar, text="← 返回主界面", width=12,
                  font=("Microsoft YaHei", 10),
                  command=self.app.show_home).pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(toolbar, text="隔离浏览器",
                 font=("Microsoft YaHei", 12, "bold")).pack(side=tk.LEFT)

        tk.Button(toolbar, text="退出程序", width=10,
                  font=("Microsoft YaHei", 12, "bold"),
                  command=self.app.quit_all).pack(side=tk.RIGHT, padx=4)

        info = tk.Label(
            parent,
            text="在独立窗口中打开可疑链接。\n"
                 "· Cookie / 缓存独立，不影响系统浏览器\n"
                 "· 无痕模式，关闭窗口后清空\n"
                 "· 请勿在此窗口登录任何账号\n"
                 "· 部分网站拒绝被嵌入，会显示「在系统浏览器打开」",
            justify=tk.LEFT, anchor="w",
            font=("Microsoft YaHei", 10),
            bg="#eef3ff", fg="#2d6cdf",
            padx=16, pady=12)
        info.pack(fill=tk.X, padx=6, pady=(12, 6))

        input_frame = tk.Frame(parent)
        input_frame.pack(fill=tk.X, padx=6, pady=(6, 0))

        tk.Label(input_frame, text="URL:",
                 font=("Microsoft YaHei", 10)).pack(side=tk.LEFT)

        self.url_var = tk.StringVar(value="about:blank")
        entry = tk.Entry(input_frame, textvariable=self.url_var,
                         font=("Consolas", 11))
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        entry.bind("<Return>", lambda e: self.open_current())

        tk.Button(input_frame, text="打开",
                  font=("Microsoft YaHei", 10, "bold"),
                  command=self.open_current).pack(side=tk.LEFT, padx=2)

        quick_frame = tk.Frame(parent)
        quick_frame.pack(fill=tk.X, padx=6, pady=(8, 0))

        tk.Label(quick_frame, text="常用:",
                 font=("Microsoft YaHei", 10),
                 fg="#777").pack(side=tk.LEFT, padx=(0, 6))

        for name, url in [
            ("VirusTotal", "https://www.virustotal.com"),
            ("URLScan", "https://urlscan.io"),
            ("IP 查询", "https://ip.sb"),
            ("百度", "https://www.baidu.com"),
            ("Bing", "https://www.bing.com"),
        ]:
            tk.Button(
                quick_frame, text=name, width=10,
                font=("Microsoft YaHei", 9),
                command=lambda u=url: open_browser(u)
            ).pack(side=tk.LEFT, padx=3)

        tk.Button(
            quick_frame, text="空白页", width=8,
            font=("Microsoft YaHei", 9),
            command=lambda: open_browser("about:blank")
        ).pack(side=tk.LEFT, padx=3)

        self.status_var = tk.StringVar(value="就绪")
        tk.Label(parent, textvariable=self.status_var, anchor="w",
                 font=("Microsoft YaHei", 9),
                 relief=tk.SUNKEN, bd=1).pack(fill=tk.X, side=tk.BOTTOM)

        if not HAS_WEBVIEW:
            tk.Label(
                parent,
                text="⚠ 未安装 pywebview，浏览器不可用\n"
                     "请执行: pip install pywebview",
                font=("Microsoft YaHei", 11),
                fg="#a11", bg="#ffdede",
                padx=12, pady=10
            ).pack(fill=tk.X, padx=6, pady=(12, 0))
            self.status_var.set("缺少 pywebview 依赖")

    def on_show(self):
        super().on_show()

    def open_current(self):
        url = self.url_var.get().strip()
        if not url or url == "about:blank":
            open_browser("about:blank")
            return
        if not url.startswith(("http://", "https://", "about:")):
            url = "https://" + url
        open_browser(url)
        self.status_var.set(f"已打开: {url}")