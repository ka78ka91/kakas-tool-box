import subprocess
import sys
import time
import os
import json
import psutil


# ================= 路径兼容 =================
if getattr(sys, "frozen", False):
    BASE = os.path.dirname(sys.executable)
else:
    BASE = os.path.dirname(os.path.abspath(__file__))

MAIN = os.path.join(BASE, "main.py")
MAIN_EXE = os.path.join(BASE, "工具箱.exe")
LOCK = os.path.join(BASE, "guard.lock")
GUARD_PID = os.path.join(BASE, "guard.pid")

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def is_pid_alive(pid):
    try:
        return psutil.pid_exists(pid)
    except Exception:
        return False


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def write_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass


def launch_main():
    """启动主程序。打包后调 exe，源码运行调 python main.py。"""
    if getattr(sys, "frozen", False):
        # 打包后
        if os.path.exists(MAIN_EXE):
            subprocess.Popen(
                [MAIN_EXE],
                creationflags=CREATE_NO_WINDOW)
        else:
            # 回退：如果 exe 不在，用 python 调 main.py
            if os.path.exists(MAIN):
                subprocess.Popen(
                    [sys.executable, MAIN],
                    creationflags=CREATE_NO_WINDOW)
    else:
        # 源码运行
        subprocess.Popen(
            [sys.executable, MAIN],
            creationflags=CREATE_NO_WINDOW)


# ================= 主循环 =================
write_json(GUARD_PID, {"guard_pid": os.getpid()})

try:
    while True:
        time.sleep(0.1)

        if not os.path.exists(LOCK):
            break

        data = read_json(LOCK)

        if data and data.get("exit"):
            break

        main_pid = data.get("main_pid") if data else None

        if not main_pid or not is_pid_alive(main_pid):
            launch_main()
            time.sleep(0.1)

finally:
    try:
        os.remove(GUARD_PID)
    except OSError:
        pass