"""
Win32 句柄扫描底层封装。

两个引擎：
- scan_handles_nt():    NtQuerySystemInformation 遍历系统句柄（需管理员）
- scan_handles_rm():    RestartManager 官方接口（无需管理员）

两者独立，调用方自行合并结果。
"""

import ctypes
from ctypes import wintypes
import os
import threading

# ================= DLL =================
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
rstrtmgr = ctypes.WinDLL("rstrtmgr", use_last_error=True)


# ================= NTSTATUS =================
STATUS_SUCCESS = 0
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
STATUS_BUFFER_OVERFLOW = 0x80000005
STATUS_BUFFER_TOO_SMALL = 0xC0000023


# ================= 结构体 =================
class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_wchar_p),
    ]


class OBJECT_NAME_INFORMATION(ctypes.Structure):
    _fields_ = [("Name", UNICODE_STRING)]


class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    _fields_ = [
        ("Object", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_void_p),
        ("HandleValue", ctypes.c_void_p),
        ("GrantedAccess", ctypes.c_uint32),
        ("CreatorBackTraceIndex", ctypes.c_ushort),
        ("ObjectTypeIndex", ctypes.c_ushort),
        ("HandleAttributes", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


class SYSTEM_HANDLE_INFORMATION_EX(ctypes.Structure):
    _fields_ = [
        ("NumberOfHandles", ctypes.c_void_p),
        ("Reserved", ctypes.c_void_p),
        ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * 1),
    ]


# SystemExtendedHandleInformation = 64
SYSTEM_EXTENDED_HANDLE_INFORMATION = 64


# ================= 基础 API =================
OpenProcess = kernel32.OpenProcess
CloseHandle = kernel32.CloseHandle
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

NtQueryObject = ntdll.NtQueryObject
NtQuerySystemInformation = ntdll.NtQuerySystemInformation
ObjectNameInformation = 1


# ================= 设备路径映射 =================
def build_device_map():
    """返回 {\\Device\\HarddiskVolumeX: 'C:'} 映射。"""
    mapping = {}
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = f"{letter}:"
        if not os.path.exists(drive + "\\"):
            continue
        try:
            buf = ctypes.create_unicode_buffer(1024)
            kernel32.QueryDosDeviceW(drive, buf, 1024)
            target = buf.value  # 形如 \Device\HarddiskVolume3
            if target:
                mapping[target.lower()] = drive
        except Exception:
            pass
    return mapping


# ================= 句柄类型探测 =================
class SYSTEM_HANDLE_TABLE_ENTRY_INFO(ctypes.Structure):
    _fields_ = [
        ("Object", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_ushort),
        ("HandleValue", ctypes.c_ushort),
        ("GrantedAccess", ctypes.c_uint32),
        ("CreatorBackTraceIndex", ctypes.c_ushort),
        ("ObjectTypeIndex", ctypes.c_ushort),
        ("HandleAttributes", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


class SYSTEM_HANDLE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("NumberOfHandles", ctypes.c_uint32),
        ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO * 1),
    ]


SYSTEM_HANDLE_INFORMATION_CLASS = 16


def _get_file_type_index():
    """查询 ObjectTypesInformation，找到 "File" 类型对应的索引。
    返回 None 表示失败。"""
    SystemObjectTypesInformation = 3

    # 先问大小
    size = ctypes.c_ulong(0)
    status = NtQuerySystemInformation(
        SystemObjectTypesInformation, None, 0, ctypes.byref(size))
    if status not in (STATUS_INFO_LENGTH_MISMATCH, STATUS_BUFFER_TOO_SMALL,
                      STATUS_BUFFER_OVERFLOW):
        return None
    if size.value == 0:
        return None

    buf = ctypes.create_string_buffer(size.value)
    status = NtQuerySystemInformation(
        SystemObjectTypesInformation, buf, size.value, ctypes.byref(size))
    if status != STATUS_SUCCESS:
        return None

    # 结构布局：
    #   ULONG NumberOfTypes
    #   struct { USHORT Level; USHORT Index; ULONG TotalNumberOfObjects;
    #            ULONG TotalNumberOfHandles;
    #            ULONG HighWaterNumberOfObjects; ULONG HighWaterNumberOfHandles;
    #            WCHAR TypeName... }
    offset = ctypes.sizeof(ctypes.c_ulong)
    num_types = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ulong))[0]

    for _ in range(num_types):
        if offset + 8 > size.value:
            break
        level = ctypes.cast(ctypes.byref(buf, offset),
                            ctypes.POINTER(ctypes.c_ushort))[0]
        index = ctypes.cast(ctypes.byref(buf, offset + 2),
                            ctypes.POINTER(ctypes.c_ushort))[0]
        offset += 8
        offset += 4 * 4   # TotalNumberOfObjects/Handles, HighWater

        # TypeName 是 WCHAR 数组，直到 4 字节对齐
        start = offset
        while offset + 1 < size.value:
            ch = ctypes.cast(ctypes.byref(buf, offset),
                             ctypes.POINTER(ctypes.c_wchar))[0]
            if ch == "\x00":
                break
            offset += 2
        name = buf.raw[start:offset].decode("utf-16-le", errors="replace")
        offset += 2
        # 对齐到 4
        if offset % 4:
            offset += 4 - (offset % 4)

        if name.lower() == "file":
            return index

    return None


# ================= 单个句柄名查询（带超时） =================
def _query_object_name(handle):
    """查询句柄对应的对象名。返回 (ok, name_str)。"""
    size = ctypes.c_ulong(0x400)
    buf = ctypes.create_string_buffer(size.value)
    status = NtQueryObject(handle, ObjectNameInformation, buf,
                           size.value, ctypes.byref(size))
    if status == STATUS_INFO_LENGTH_MISMATCH:
        buf = ctypes.create_string_buffer(size.value)
        status = NtQueryObject(handle, ObjectNameInformation, buf,
                               size.value, ctypes.byref(size))
    if status != STATUS_SUCCESS:
        return False, ""
    try:
        info = ctypes.cast(buf, ctypes.POINTER(OBJECT_NAME_INFORMATION)).contents
        if not info.Name.Buffer:
            return False, ""
        return True, info.Name.Buffer
    except Exception:
        return False, ""


def _query_with_timeout(handle, timeout=0.3):
    """在子线程查句柄名，超时就放弃（NtQueryObject 对管道会永久阻塞）。"""
    result = [None]

    def worker():
        try:
            result[0] = _query_object_name(handle)
        except Exception:
            result[0] = (False, "")

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return False, ""
    return result[0] or (False, "")


# ================= 引擎 A：NT 全句柄扫描 =================
def scan_handles_nt(target_path, progress_cb=None):
    """遍历系统所有句柄，返回持有 target_path 的进程列表。

    每项: {
        "pid": int,
        "handle": int,
        "path": str,       # 命中时的文件路径（已转盘符）
        "source": "A"
    }
    """
    target = os.path.normcase(os.path.abspath(target_path))

    file_type_index = _get_file_type_index()
    if file_type_index is None:
        # 找不到 File 类型索引，放弃
        return []

    device_map = build_device_map()

    # 拿全量句柄表
    size = ctypes.c_ulong(1 << 20)
    buf = None
    for _ in range(6):
        buf = ctypes.create_string_buffer(size.value)
        ret_len = ctypes.c_ulong(0)
        status = NtQuerySystemInformation(
            SYSTEM_EXTENDED_HANDLE_INFORMATION,
            buf, size.value, ctypes.byref(ret_len))
        if status == STATUS_INFO_LENGTH_MISMATCH:
            size.value = ret_len.value + (1 << 16)
            continue
        if status != STATUS_SUCCESS:
            return []
        break
    else:
        return []

    header = ctypes.cast(
        buf, ctypes.POINTER(SYSTEM_HANDLE_INFORMATION_EX)).contents
    count = int(header.NumberOfHandles)
    if count <= 0:
        return []

    # Handles 数组紧随 header 之后
    arr_offset = ctypes.sizeof(ctypes.c_void_p) * 2
    arr_type = SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * count
    entries = arr_type.from_buffer(buf, arr_offset)

    found = []
    seen = set()   # (pid, handle)
    processed = 0

    for i in range(count):
        e = entries[i]
        processed += 1
        if progress_cb and processed % 500 == 0:
            try:
                progress_cb(processed, count)
            except Exception:
                pass

        if e.ObjectTypeIndex != file_type_index:
            continue

        pid = int(e.UniqueProcessId or 0)
        handle_val = int(e.HandleValue or 0)
        if pid == 0 or handle_val == 0:
            continue
        if pid == 4:
            # System 进程：无法直接打开，记录一下但不查名字
            # （后续如需可标记为系统占用）
            continue
        if (pid, handle_val) in seen:
            continue
        seen.add((pid, handle_val))

        hproc = OpenProcess(PROCESS_DUP_HANDLE, False, pid)
        if not hproc:
            continue
        try:
            hdup = wintypes.HANDLE()
            ok = kernel32.DuplicateHandle(
                hproc, wintypes.HANDLE(handle_val),
                kernel32.GetCurrentProcess(), ctypes.byref(hdup),
                0, False, 0x00000002)  # DUPLICATE_SAME_ACCESS
            if not ok:
                continue
            try:
                ok2, name = _query_with_timeout(hdup, timeout=0.3)
            finally:
                CloseHandle(hdup)
            if not ok2 or not name:
                continue
            # 只关心 \Device\... 这类路径
            low = name.lower()
            if not low.startswith("\\device\\"):
                continue

            # 转盘符
            real = name
            for dev, drive in device_map.items():
                if low.startswith(dev):
                    real = drive + name[len(dev):]
                    break

            real_norm = os.path.normcase(os.path.abspath(real))
            if real_norm == target:
                found.append({
                    "pid": pid,
                    "handle": handle_val,
                    "path": real,
                    "source": "A",
                })
        finally:
            CloseHandle(hproc)

    return found


# ================= 引擎 C：RestartManager =================
CCH_RM_MAX_APP_NAME = 255
CCH_RM_MAX_SVC_NAME = 63


class RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [
        ("dwProcessId", wintypes.DWORD),
        ("ProcessStartTime", wintypes.FILETIME),
    ]


class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [
        ("Process", RM_UNIQUE_PROCESS),
        ("strAppName", wintypes.WCHAR * (CCH_RM_MAX_APP_NAME + 1)),
        ("strServiceShortName", wintypes.WCHAR * (CCH_RM_MAX_SVC_NAME + 1)),
        ("ApplicationType", ctypes.c_uint),
        ("AppStatus", wintypes.ULONG),
        ("TSSessionId", wintypes.DWORD),
        ("bRestartable", wintypes.BOOL),
    ]


def scan_handles_rm(target_path):
    """用 RestartManager 查询占用目标文件的进程。
    返回: [{"pid":..., "name":..., "source": "C", "restartable": bool}]
    """
    target = os.path.abspath(target_path)
    if not os.path.exists(target):
        return []

    session = wintypes.DWORD()
    session_key = ctypes.create_unicode_buffer(256 + 1)

    ret = rstrtmgr.RmStartSession(ctypes.byref(session), 0, session_key)
    if ret != 0:
        return []

    try:
        files = (wintypes.LPCWSTR * 1)(target)
        ret = rstrtmgr.RmRegisterResources(
            session, 1, files, 0, None, 0, None)
        if ret != 0:
            return []

        # 第一次问所需大小
        needed = wintypes.UINT(0)
        count = wintypes.UINT(0)
        reason = wintypes.DWORD(0)
        ret = rstrtmgr.RmGetList(
            session, ctypes.byref(needed), ctypes.byref(count),
            None, ctypes.byref(reason))

        RM_MORE_DATA = 234
        if ret not in (0, RM_MORE_DATA):
            return []
        if needed.value == 0:
            return []

        arr = (RM_PROCESS_INFO * needed.value)()
        count = wintypes.UINT(needed.value)
        ret = rstrtmgr.RmGetList(
            session, ctypes.byref(needed), ctypes.byref(count),
            arr, ctypes.byref(reason))
        if ret != 0:
            return []

        results = []
        for i in range(count.value):
            info = arr[i]
            pid = info.Process.dwProcessId
            if not pid:
                continue
            results.append({
                "pid": pid,
                "name": info.strAppName or "",
                "source": "C",
                "restartable": bool(info.bRestartable),
            })
        return results
    finally:
        try:
            rstrtmgr.RmEndSession(session)
        except Exception:
            pass


# ================= 合并入口 =================
def find_holders(target_path, use_nt=True, progress_cb=None):
    """双引擎合并，去重后返回统一列表。

    每项: {
        "pid": int,
        "name": str,        # 进程名
        "exe": str,
        "source": str,      # "A" / "C" / "A+C"
        "restartable": bool,
        "is_system": bool,
    }
    """
    import psutil

    merged = {}

    # 引擎 C
    try:
        for r in scan_handles_rm(target_path):
            merged.setdefault(r["pid"], {
                "pid": r["pid"],
                "name": r["name"],
                "exe": "",
                "source": set(),
                "restartable": r.get("restartable", False),
                "is_system": False,
            })["source"].add("C")
    except Exception:
        pass

    # 引擎 A
    if use_nt:
        try:
            for r in scan_handles_nt(target_path, progress_cb=progress_cb):
                pid = r["pid"]
                if pid in merged:
                    merged[pid]["source"].add("A")
                else:
                    merged[pid] = {
                        "pid": pid,
                        "name": "",
                        "exe": "",
                        "source": {"A"},
                        "restartable": False,
                        "is_system": False,
                    }
        except Exception:
            pass

    # 补全名称 / 路径
    out = []
    for pid, info in merged.items():
        if not info["name"] or not info["exe"]:
            try:
                p = psutil.Process(pid)
                info["name"] = info["name"] or (p.name() or "未知")
                try:
                    info["exe"] = p.exe() or ""
                except Exception:
                    pass
                if pid in (0, 4):
                    info["is_system"] = True
            except Exception:
                info["name"] = info["name"] or f"PID {pid}"
        info["source"] = "+".join(sorted(info["source"]))
        out.append(info)

    out.sort(key=lambda x: (x["is_system"], x["name"].lower()))
    return out