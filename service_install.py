"""
服务安装/卸载的便捷脚本，双击运行即可。
会自动请求管理员权限。
"""

import ctypes
import sys
import os
import subprocess


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_as_admin():
    """如果不是管理员，以管理员身份重新启动自己。"""
    if is_admin():
        return False
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable,
        " ".join([f'"{a}"' for a in sys.argv]),
        None, 1)
    return True


def main():
    if run_as_admin():
        sys.exit(0)

    base = os.path.dirname(os.path.abspath(__file__))
    service_py = os.path.join(base, "service.py")

    print("=" * 50)
    print("  工具箱守护服务")
    print("=" * 50)
    print()
    print("  1. 安装服务（开机自启 + 守护 GUI）")
    print("  2. 卸载服务")
    print("  3. 启动服务")
    print("  4. 停止服务")
    print("  5. 前台调试")
    print("  0. 退出")
    print()

    choice = input("请选择 [0-5]: ").strip()

    cmd_map = {
        "1": "install",
        "2": "remove",
        "3": "start",
        "4": "stop",
        "5": "debug",
    }

    if choice == "0":
        return
    if choice not in cmd_map:
        print("无效选择")
        input("按回车退出…")
        return

    subprocess.run([sys.executable, service_py, cmd_map[choice]])
    input("\n按回车退出…")


if __name__ == "__main__":
    main()