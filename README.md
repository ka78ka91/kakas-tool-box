# Kakas Tool Box

一个 Windows 系统管理工具箱，集成多种实用工具。

## 功能

- 📋 任务管理器 - 查看、搜索、结束系统进程
- 🪟 窗口管理 - 关闭窗口、切换焦点、置顶
- 🔓 文件解锁 - 找出占用文件的进程并结束
- 🛰️ 远控检测 - 扫描远控软件、远程桌面、可疑连接
- 🌐 隔离浏览器 - 打开可疑链接的安全窗口
- 📜 日志查看
- ℹ️ 关于

## 运行环境

- Windows 10 / 11
- Python 3.10+

## 安装

pip install psutil pywin32 pystray pillow webview tkinterdnd2

## 运行

python main.py

建议以管理员身份运行以获得完整功能。

## 打包

pyinstaller --onedir --windowed --name=工具箱 --collect-all tkinterdnd2 --collect-all webview --hidden-import=PIL._tkinter_finder --hidden-import=win32timezone --noconfirm main.py

## 许可证

MIT