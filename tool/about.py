import tkinter as tk
from tkinter import ttk
import os
import sys
import platform
import psutil

import common
from common import logger, BASE
from tool import Tool


VERSION = "0.3.0"


class AboutTool(Tool):
    name = "about"
    display_name = "关于"
    description = "版本信息、快捷键、使用说明"
    icon = "ℹ️"

    def __init__(self, app):
        super().__init__(app)
        self.frame = None

    def build(self, parent):
        self.frame = parent

        toolbar = tk.Frame(parent)
        toolbar.pack(fill=tk.X, padx=6, pady=(6, 0))

        tk.Button(toolbar, text="← 返回主界面", width=12,
                  font=("Microsoft YaHei", 10),
                  command=self.app.show_home).pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(toolbar, text="关于",
                 font=("Microsoft YaHei", 12, "bold")).pack(side=tk.LEFT)

        tk.Button(toolbar, text="退出程序", width=10,
                  font=("Microsoft YaHei", 12, "bold"),
                  command=self.app.quit_all).pack(side=tk.RIGHT, padx=4)

        # 内容
        text_frame = tk.Frame(parent)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        txt = tk.Text(text_frame, wrap="word",
                      font=("Microsoft YaHei", 10),
                      relief=tk.FLAT, bd=0)
        txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        vsb = ttk.Scrollbar(text_frame, orient="vertical",
                            command=txt.yview)
        txt.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # 内容
        content = self._build_content()
        txt.insert(tk.END, content)
        txt.configure(state="disabled")

        # 标签颜色
        txt.tag_configure("h1", font=("Microsoft YaHei", 14, "bold"),
                          spacing1=8, spacing3=8)
        txt.tag_configure("h2", font=("Microsoft YaHei", 12, "bold"),
                          spacing1=6, spacing3=4)
        txt.tag_configure("code", font=("Consolas", 9),
                          background="#f0f0f0")

        # 重新应用 tag（先插后加 tag 无法定位，用简单方式重排）
        txt.configure(state="normal")
        txt.delete("1.0", tk.END)
        for line in content.split("\n"):
            if line.startswith("# "):
                txt.insert(tk.END, line[2:] + "\n", "h1")
            elif line.startswith("## "):
                txt.insert(tk.END, line[3:] + "\n", "h2")
            else:
                txt.insert(tk.END, line + "\n")
        txt.configure(state="disabled")

    def _build_content(self):
        lines = [
            f"# 工具箱 v{VERSION}",
            "",
            "一个开源的 Windows 系统管理与安全工具集合。",
            "",
            "## 环境信息",
            f"Python: {sys.version.split()[0]}",
            f"系统: {platform.system()} {platform.release()}",
            f"版本: {platform.version()}",
            f"工作目录: {BASE}",
            "",
            "## 已安装工具",
        ]
        for tool in self.app.tools.values():
            lines.append(f"  {tool.icon}  {tool.display_name}")
            lines.append(f"      {tool.description}")

        lines += [
            "",
            "## 快捷键",
            "  F5              刷新当前工具",
            "  Ctrl+F          聚焦搜索框",
            "  Esc             清空搜索 / 返回主页",
            "  Delete          结束选中的进程 / 关闭窗口",
            "  Ctrl+1 ~ Ctrl+9 切换到第 N 个工具",
            "  Alt+F4          无操作（防误关）",
            "",
            "## 托盘",
            "  勾选「最小化到托盘」后，关闭窗口会隐藏到托盘。",
            "  双击托盘图标恢复窗口，右键菜单可以退出。",
            "",
            "## 开机自启",
            "  勾选「开机自启」后，每次登录 Windows 会自动启动。",
            "  写入位置：HKCU\\Software\\Microsoft\\Windows\\"
            "CurrentVersion\\Run",
            "",
            "## 安全说明",
            "  · 本工具需要管理员权限才能启用完整功能",
            "  · 关键进程保护开启时，强杀本程序会导致系统蓝屏",
            "  · 所有操作都会写入 taskmgr.log",
            "",
            "## 常见问题",
            "  Q: 为什么某些进程无法结束？",
            "  A: 权限不足。请以管理员身份运行。",
            "",
            "  Q: 为什么端口/句柄扫描结果少？",
            "  A: 非管理员模式只跑 RestartManager 引擎，"
            "建议以管理员运行。",
            "",
            "  Q: 怎么彻底卸载？",
            "  A: 删除本目录 + 删除 %APPDATA%\\Toolbox + "
            "取消开机自启。",
            "",
        ]
        return "\n".join(lines)