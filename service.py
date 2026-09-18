"""
Windows 服务入口。
服务本身只负责守护逻辑：
  - 检测 main.py（GUI）是否在跑
  - 不在就通过计划任务在用户会话中拉起它
  - 无 GUI、无窗口、无用户交互

用法：
  python service.py install    安装并启动服务（需要管理员）
  python service.py remove     停止并卸载服务（需要管理员）
  python service.py start      启动服务
  python service.py stop       停止服务
  python service.py debug      前台运行（调试用）
"""
import os
import sys
import time
import json
import subprocess
import threading
import logging
import traceback
from logging.handlers import RotatingFileHandler

# ---------- 关键：服务模式下修正路径 ----------
_HERE = os.path.dirname(os.path.abspath(__file__))
# 加入 sys.path，让 import common / import tool 能工作
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
# 切换工作目录，让所有相对路径（如 .log）写到项目目录
try:
    os.chdir(_HERE)
except Exception:
    pass

# ---------- 路径 ----------
BASE = _HERE
MAIN_PY = os.path.join(BASE, "main.py")
LOG_FILE = os.path.join(BASE, "service.log")
LOCK = os.path.join(BASE, "guard.lock")
GUARD_PID = os.path.join(BASE, "guard.pid")

SERVICE_NAME = "ToolboxGuard"
SERVICE_DISPLAY = "工具箱守护服务"
SERVICE_DESC = "保持工具箱主程序运行，被关闭后自动重启"

CHECK_INTERVAL = 3       # 秒
TASK_NAME = "ToolboxAutoStart"

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


# ---------- 日志 ----------
logger = logging.getLogger("toolbox_service")
logger.setLevel(logging.INFO)
if not logger.handlers:
    _h = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000,
                             backupCount=3, encoding="utf-8")
    _h.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(_h)


def is_pid_alive(pid):
    try:
        import psutil
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


# ---------- 启动 GUI（在用户会话中） ----------
def launch_gui():
    """通过计划任务在用户会话中启动 GUI。
    服务运行在 Session 0，直接 Popen 拉起的进程用户看不到，
    必须用计划任务切到用户会话。
    """
    try:
        # 先看是不是已经在跑
        data = read_json(LOCK)
        if data and data.get("main_pid"):
            if is_pid_alive(data["main_pid"]):
                return
        # 没在跑，用 schtasks 触发
        subprocess.run(
            ["schtasks", "/Run", "/TN", TASK_NAME],
            capture_output=True, timeout=10,
            creationflags=CREATE_NO_WINDOW)
        logger.info("已通过计划任务拉起 GUI")
    except Exception as e:
        logger.error(f"拉起 GUI 失败: {e}")


def check_main():
    """检查主进程是否存活。"""
    data = read_json(LOCK)
    if not data:
        return False
    pid = data.get("main_pid")
    if not pid:
        return False
    return is_pid_alive(pid)


# ---------- 守护循环 ----------
_stop_event = threading.Event()


def guard_loop():
    """核心循环：主进程死了就拉起来。"""
    logger.info("守护循环已启动")
    miss_count = 0

    while not _stop_event.is_set():
        try:
            if not check_main():
                miss_count += 1
                # 连续两次检测都失败才拉起，防止误判
                if miss_count >= 2:
                    logger.warning(f"主进程未运行（连续 {miss_count} 次），"
                                   f"尝试拉起")
                    launch_gui()
                    miss_count = 0
            else:
                miss_count = 0
        except Exception as e:
            logger.error(f"守护循环异常: {e}")

        _stop_event.wait(CHECK_INTERVAL)

    logger.info("守护循环已停止")


# ---------- 服务主体 ----------
try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False


if HAS_WIN32:
    class ToolboxService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY
        _svc_description_ = SERVICE_DESC

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self._thread = None

        def SvcStop(self):
            logger.info("收到停止请求")
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            _stop_event.set()
            win32event.SetEvent(self.hWaitStop)

        def SvcDoRun(self):
            try:
                servicemanager.LogInfoMsg(f"{SERVICE_NAME} 正在启动")
                logger.info("服务启动")

                self._thread = threading.Thread(
                    target=guard_loop, daemon=True)
                self._thread.start()

                # 等待停止信号
                win32event.WaitForSingleObject(self.hWaitStop,
                                               win32event.INFINITE)
                logger.info("服务已停止")
            except Exception as e:
                logger.exception(f"服务异常: {e}")
                servicemanager.LogErrorMsg(f"{SERVICE_NAME} 异常: {e}")


# ---------- 计划任务（用于在用户会话拉起 GUI） ----------
def setup_scheduled_task():
    """创建计划任务，让 GUI 能在用户会话中启动。"""
    python_exe = sys.executable
    # 使用 pythonw.exe 避免黑窗口
    py_dir = os.path.dirname(python_exe)
    pythonw = os.path.join(py_dir, "pythonw.exe")
    if not os.path.exists(pythonw):
        pythonw = python_exe

    cmd = f'"{pythonw}" "{MAIN_PY}"'

    # 先删除旧的
    subprocess.run(
        ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
        capture_output=True, creationflags=CREATE_NO_WINDOW)

    # 创建：登录时启动，最高权限
    result = subprocess.run(
        ["schtasks", "/Create",
         "/TN", TASK_NAME,
         "/TR", cmd,
         "/SC", "ONLOGON",
         "/RL", "HIGHEST",
         "/F"],
        capture_output=True, creationflags=CREATE_NO_WINDOW)
    if result.returncode == 0:
        logger.info(f"计划任务 {TASK_NAME} 已创建")
        return True
    else:
        err = result.stderr.decode("gbk", errors="replace")
        logger.error(f"创建计划任务失败: {err}")
        return False


def remove_scheduled_task():
    subprocess.run(
        ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
        capture_output=True, creationflags=CREATE_NO_WINDOW)
    logger.info(f"计划任务 {TASK_NAME} 已删除")


# ---------- 命令行入口 ----------
def cmd_install():
    if not HAS_WIN32:
        print("请先安装 pywin32: pip install pywin32")
        return
    # 建计划任务
    setup_scheduled_task()
    # 安装服务
    win32serviceutil.InstallService(
        pythonClassString=f"{os.path.basename(__file__)[:-3]}"
                          f".ToolboxService",
        serviceName=SERVICE_NAME,
        displayName=SERVICE_DISPLAY,
        description=SERVICE_DESC,
        startType=win32service.SERVICE_AUTO_START,
    )
    print(f"服务 {SERVICE_NAME} 已安装，正在启动…")
    win32serviceutil.StartService(SERVICE_NAME)
    print("服务已启动")


def cmd_remove():
    if not HAS_WIN32:
        print("请先安装 pywin32")
        return
    try:
        win32serviceutil.StopService(SERVICE_NAME)
    except Exception:
        pass
    try:
        win32serviceutil.RemoveService(SERVICE_NAME)
    except Exception:
        pass
    remove_scheduled_task()
    print(f"服务 {SERVICE_NAME} 已卸载")


def cmd_start():
    win32serviceutil.StartService(SERVICE_NAME)
    print("服务已启动")


def cmd_stop():
    win32serviceutil.StopService(SERVICE_NAME)
    print("服务已停止")


def cmd_debug():
    """前台运行，方便调试。"""
    print("前台调试模式，Ctrl+C 退出")
    try:
        guard_loop()
    except KeyboardInterrupt:
        _stop_event.set()
        print("已退出")


if __name__ == "__main__":
    if not HAS_WIN32:
        print("需要 pywin32: pip install pywin32")
        sys.exit(1)

    if len(sys.argv) == 1:
        # 作为服务被 SCM 启动
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(ToolboxService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        cmd = sys.argv[1].lower()
        if cmd == "install":
            cmd_install()
        elif cmd == "remove":
            cmd_remove()
        elif cmd == "start":
            cmd_start()
        elif cmd == "stop":
            cmd_stop()
        elif cmd == "debug":
            cmd_debug()
        else:
            print("用法: python service.py "
                  "[install|remove|start|stop|debug]")