# -*- coding: utf-8 -*-
"""
内存整理 · 加强版
────────────────
1. 会清「待命列表」（Standby List）—— 多数同类工具只踢工作集，不做这一步
2. 动手前先筛：跳过前台窗口、系统关键进程、活跃进程
3. 数字拆成三条独立度量：已用 / 系统缓存 / 纯空闲，各自占多大一目了然
"""

import ctypes
import ctypes.wintypes as wt
import datetime
import os
import sys
import threading
import time
import traceback

APP = "内存整理 · 加强版"
VER = "1.1"

if getattr(sys, "frozen", False):
    BASE = os.path.dirname(sys.executable)
else:
    BASE = os.path.dirname(os.path.abspath(__file__))
LOGFILE = os.path.join(BASE, "使用记录.log")
ERRFILE = os.path.join(BASE, "启动错误.log")

# ─────────────────────────── Win32 ───────────────────────────
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
advapi = ctypes.WinDLL("advapi32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED = 0x1000
PROCESS_SET_QUOTA = 0x0100
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x0002
SystemMemoryListInformation = 80
MEM_PURGE_STANDBY = 4
MEM_PURGE_LOW_STANDBY = 5
MEM_FLUSH_MODIFIED = 3


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wt.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wt.DWORD),
                ("Privileges", LUID_AND_ATTRIBUTES * 1)]


class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [
        ("cb", wt.DWORD), ("PageFaultCount", wt.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wt.DWORD), ("dwMemoryLoad", wt.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


k32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
k32.OpenProcess.restype = wt.HANDLE
psapi.EnumProcesses.argtypes = [ctypes.POINTER(wt.DWORD), wt.DWORD, ctypes.POINTER(wt.DWORD)]
psapi.GetProcessMemoryInfo.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX), wt.DWORD]
psapi.EmptyWorkingSet.argtypes = [wt.HANDLE]
advapi.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
advapi.LookupPrivilegeValueW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, ctypes.POINTER(LUID)]
advapi.AdjustTokenPrivileges.argtypes = [wt.HANDLE, wt.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES),
                                         wt.DWORD, ctypes.c_void_p, ctypes.c_void_p]
k32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def enable_privileges():
    """清待命列表需要 SeProfileSingleProcessPrivilege。"""
    ok = []
    for name in ("SeProfileSingleProcessPrivilege", "SeIncreaseQuotaPrivilege",
                 "SeDebugPrivilege"):
        h = wt.HANDLE()
        if not advapi.OpenProcessToken(k32.GetCurrentProcess(),
                                       TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h)):
            continue
        luid = LUID()
        if not advapi.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            k32.CloseHandle(h)
            continue
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        ok_call = advapi.AdjustTokenPrivileges(h, False, ctypes.byref(tp), 0, None, None)
        # 调用成功 ≠ 特权到手，非管理员时是 ERROR_NOT_ALL_ASSIGNED
        err = ctypes.get_last_error()
        if ok_call and err == 0:
            ok.append(name)
        k32.CloseHandle(h)
    return ok


def purge_memory_list(cmd):
    val = ctypes.c_int(cmd)
    st = ntdll.NtSetSystemInformation(SystemMemoryListInformation,
                                      ctypes.byref(val), ctypes.sizeof(val))
    return st & 0xFFFFFFFF


def list_pids():
    arr = (wt.DWORD * 4096)()
    need = wt.DWORD(0)
    if not psapi.EnumProcesses(arr, ctypes.sizeof(arr), ctypes.byref(need)):
        return []
    return list(arr[: need.value // ctypes.sizeof(wt.DWORD)])


def proc_name(pid):
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED, False, pid)
    if not h:
        return None
    try:
        buf = ctypes.create_unicode_buffer(520)
        size = wt.DWORD(520)
        if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return os.path.basename(buf.value)
    finally:
        k32.CloseHandle(h)
    return None


def proc_ws(pid):
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED, False, pid)
    if not h:
        return None
    try:
        pmc = PROCESS_MEMORY_COUNTERS_EX()
        pmc.cb = ctypes.sizeof(pmc)
        if psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb):
            return int(pmc.WorkingSetSize)
    finally:
        k32.CloseHandle(h)
    return None


def trim(pid, before):
    h = k32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        return 0
    try:
        if not psapi.EmptyWorkingSet(h):
            return 0
        pmc = PROCESS_MEMORY_COUNTERS_EX()
        pmc.cb = ctypes.sizeof(pmc)
        after = before
        if psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb):
            after = int(pmc.WorkingSetSize)
        return max(0, before - after)
    finally:
        k32.CloseHandle(h)


def foreground_pid():
    hwnd = user32.GetForegroundWindow()
    pid = wt.DWORD(0)
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


_WIN_PIDS = set()


def window_pids():
    global _WIN_PIDS
    _WIN_PIDS = set()
    EnumProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)(_enum_cb)
    user32.EnumWindows(EnumProc, 0)
    return _WIN_PIDS


def _enum_cb(hwnd, _):
    try:
        if user32.IsWindowVisible(hwnd) and user32.GetWindowTextLengthW(hwnd) > 0:
            pid = wt.DWORD(0)
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value:
                _WIN_PIDS.add(pid.value)
    except Exception:
        pass
    return True


def top_processes(count=5):
    """按进程名聚合内存占用，返回 [(名字, 字节数), ...]。给用户看'该关哪个'。"""
    me = os.getpid()
    agg = {}
    for pid in list_pids():
        if pid in (0, 4, me):
            continue
        ws = proc_ws(pid)
        if not ws or ws < 8 * 1024 * 1024:
            continue
        nm = proc_name(pid)
        if not nm:
            continue
        key = nm[:-4] if nm.lower().endswith(".exe") else nm
        agg[key] = agg.get(key, 0) + ws
    items = sorted(agg.items(), key=lambda x: -x[1])
    return items[:count]


# ───────────────────────── 内存数字（PDH） ─────────────────────────
class MemStats(object):
    def __init__(self):
        self.total = 0
        self.avail = 0
        self.standby = 0
        self.modified = 0
        self.free_zero = 0
        self._q = None
        self._c = {}

    def open(self):
        try:
            pdh = ctypes.WinDLL("pdh")
            q = wt.HANDLE()
            if pdh.PdhOpenQueryW(None, 0, ctypes.byref(q)) != 0:
                return False
            self._q = q
            self._pdh = pdh
            for key, path in {
                "standby_normal": r"\Memory\Standby Cache Normal Priority Bytes",
                "standby_reserve": r"\Memory\Standby Cache Reserve Bytes",
                "standby_core": r"\Memory\Standby Cache Core Bytes",
                "modified": r"\Memory\Modified Page List Bytes",
                "free_zero": r"\Memory\Free & Zero Page List Bytes",
            }.items():
                hc = wt.HANDLE()
                if pdh.PdhAddEnglishCounterW(q, path, 0, ctypes.byref(hc)) == 0:
                    self._c[key] = hc
            return True
        except Exception:
            return False

    def refresh(self):
        ms = MEMORYSTATUSEX()
        ms.dwLength = ctypes.sizeof(ms)
        k32.GlobalMemoryStatusEx(ctypes.byref(ms))
        self.total = int(ms.ullTotalPhys)
        self.avail = int(ms.ullAvailPhys)

        if not self._q:
            self.standby = 0
            self.modified = 0
            self.free_zero = max(0, self.total - self.avail)
            return self

        pdh = self._pdh
        pdh.PdhCollectQueryData(self._q)

        class VAL(ctypes.Structure):
            _fields_ = [("CStatus", wt.DWORD), ("doubleValue", ctypes.c_double)]

        def read(key):
            hc = self._c.get(key)
            if not hc:
                return 0
            v = VAL()
            if pdh.PdhGetFormattedCounterValue(hc, 0x00000200, None, ctypes.byref(v)) == 0:
                return int(v.doubleValue)
            return 0

        self.standby = (read("standby_normal") + read("standby_reserve")
                        + read("standby_core"))
        self.modified = read("modified")
        self.free_zero = read("free_zero")
        return self

    def close(self):
        if self._q:
            try:
                self._pdh.PdhCloseQuery(self._q)
            except Exception:
                pass
            self._q = None

    @property
    def used(self):
        return max(0, self.total - self.avail)


# ─────────────────────────── 清理逻辑 ───────────────────────────
MODE_LIGHT, MODE_STD, MODE_DEEP = "light", "standard", "deep"
MODE_CN = {MODE_LIGHT: "轻度", MODE_STD: "标准", MODE_DEEP: "深度"}

CRITICAL = {
    "system", "idle", "registry", "memory compression", "secure system",
    "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "smss.exe", "dwm.exe", "fontdrvhost.exe", "audiodg.exe", "svchost.exe",
    "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe", "wudfhost.exe",
    "explorer.exe", "searchhost.exe", "startmenuexperiencehost.exe",
    "shellexperiencehost.exe", "textinputhost.exe", "ctfmon.exe",
}
MIN_WS = 60 * 1024 * 1024


class Result(object):
    def __init__(self):
        self.before = None
        self.after = None
        self.mode = MODE_LIGHT
        self.purge_status = []
        self.purged = False
        self.trimmed = 0
        self.trim_count = 0
        self.skipped = 0
        self.candidates = 0
        self.elapsed = 0.0
        self.lines = []


def _snap(stats):
    return type("S", (), {k: getattr(stats, k) for k in
                          ("total", "avail", "standby", "modified", "free_zero", "used")})()


def run_clean(mode, stats, on_log=None):
    r = Result()
    r.mode = mode
    t0 = time.time()

    def log(s, tag=None):
        r.lines.append(s)
        if on_log:
            on_log(s, tag)

    stats.refresh()
    r.before = _snap(stats)

    privs = enable_privileges()

    for cmd, label in ((MEM_FLUSH_MODIFIED, "刷已修改页"),
                       (MEM_PURGE_LOW_STANDBY, "清低优先级待命"),
                       (MEM_PURGE_STANDBY, "清待命列表")):
        r.purge_status.append((label, purge_memory_list(cmd)))

    bad = [l for l, s in r.purge_status if s != 0]
    if not bad:
        purge_txt = "清待命 ✓"
    elif len(bad) == len(r.purge_status):
        purge_txt = "清待命 ✗ 权限不足"
    else:
        purge_txt = "清待命 部分失败"
    log("模式：%s　|　%s　|　特权 %d 项" % (MODE_CN[mode], purge_txt, len(privs)), "ok")

    r.purged = any(s == 0 for label, s in r.purge_status if "待命" in label)

    if mode != MODE_LIGHT:
        fg = foreground_pid()
        win = window_pids()
        me = os.getpid()
        pids = list_pids()

        targets = []
        for pid in pids:
            if pid in (0, 4, me) or pid == fg:
                continue
            nm = proc_name(pid)
            if not nm or nm.lower() in CRITICAL:
                r.skipped += 1
                continue
            ws = proc_ws(pid)
            if not ws or ws < MIN_WS:
                continue
            if mode == MODE_STD and pid in win:
                r.skipped += 1
                continue
            targets.append((pid, nm, ws))

        targets.sort(key=lambda x: -x[2])
        r.candidates = len(targets)
        for pid, nm, ws in targets:
            got = trim(pid, ws)
            if got:
                r.trimmed += got
                r.trim_count += 1

        log("扫描 %d 个进程 → 压缩 %d 个（%.0f MB 转入缓存/页面文件）"
            % (len(pids), r.trim_count, r.trimmed / 1048576.0))
        if r.skipped:
            log("跳过 %d 个（前台窗口 / 系统关键 / 体积太小）" % r.skipped, "dim")
        if not r.purged:
            log("⚠ 待命没清掉：这些页面仍在内存里，只是不再算「已用」", "warn")

    time.sleep(0.4)
    stats.refresh()
    r.after = _snap(stats)
    r.elapsed = time.time() - t0
    return r


# ─────────────────────────── 界面 ───────────────────────────
import tkinter as tk

BG = "#0F1116"
CARD = "#171A20"
CARD2 = "#20242C"
TXT = "#E9ECF2"
SUB = "#868D9B"
DIM = "#59606D"
ACCENT = "#4C8DFF"
ACCENT_HI = "#6BA3FF"
USED = "#FF6B57"
STANDBY = "#E0A23C"
FREE = "#35D0A5"

F_UI = ("Microsoft YaHei UI", 10)
F_SM = ("Microsoft YaHei UI", 9)
F_TINY = ("Microsoft YaHei UI", 8)
F_NUM = ("Consolas", 21, "bold")
F_BTN = ("Microsoft YaHei UI", 12, "bold")


def gb(v):
    if v is None:
        return "—"
    if v >= 1024 ** 3:
        return "%.2f GB" % (v / 1024.0 ** 3)
    return "%d MB" % round(v / 1048576.0)


class Btn(tk.Frame):
    def __init__(self, parent, text, cmd, primary=False, size=F_UI):
        self._primary = primary
        self._bg = ACCENT if primary else CARD2
        self._hover = ACCENT_HI if primary else "#282D37"
        self._fg = "#FFFFFF" if primary else SUB
        tk.Frame.__init__(self, parent, bg=self._bg, highlightthickness=0)
        self._cmd = cmd
        self.lbl = tk.Label(self, text=text, bg=self._bg, fg=self._fg, font=size,
                            padx=42 if primary else 20, pady=13 if primary else 8,
                            cursor="hand2")
        self.lbl.pack()
        self._enabled = True
        for w in (self, self.lbl):
            w.bind("<Enter>", self._in)
            w.bind("<Leave>", self._out)
            w.bind("<Button-1>", self._click)

    def _in(self, e):
        if self._enabled:
            self.lbl.configure(bg=self._hover)
            self.configure(bg=self._hover)

    def _out(self, e):
        self.lbl.configure(bg=self._bg)
        self.configure(bg=self._bg)

    def _click(self, e):
        if self._enabled:
            self._cmd()

    def set_enabled(self, on):
        self._enabled = on
        base = self._bg if on else CARD
        self.configure(bg=base)
        self.lbl.configure(bg=base, fg=self._fg if on else DIM)

    def set_text(self, t):
        self.lbl.configure(text=t)


class Metric(tk.Frame):
    """一行度量：名称 + 说明 + 数值 + 占比条"""

    def __init__(self, parent, title, hint, color):
        tk.Frame.__init__(self, parent, bg=BG)
        self.color = color
        self._ratio = 0.0

        head = tk.Frame(self, bg=BG)
        head.pack(fill="x")
        tk.Label(head, text=title, bg=BG, fg=TXT,
                 font=("Microsoft YaHei UI", 11)).pack(side="left")
        self.val = tk.Label(head, text="—", bg=BG, fg=color, font=F_NUM)
        self.val.pack(side="right")
        tk.Label(self, text=hint, bg=BG, fg=DIM, font=F_TINY).pack(anchor="w", pady=(0, 6))

        self.bar = tk.Canvas(self, height=9, bg=BG, highlightthickness=0)
        self.bar.pack(fill="x")
        self.bar.bind("<Configure>", lambda e: self._draw())

    def set(self, value, total, suffix=""):
        self.val.configure(text=gb(value) + (("　" + suffix) if suffix else ""))
        self._ratio = 0.0 if not total else max(0.0, min(1.0, value / float(total)))
        self._draw()

    def _draw(self):
        c = self.bar
        c.delete("all")
        w, h = c.winfo_width(), 9
        if w < 20:
            return
        r = h / 2.0
        c.create_line(r, r, w - r, r, width=h, fill=CARD2, capstyle="round")
        if self._ratio > 0.004:
            x2 = r + max(h, (w - 2 * r) * self._ratio)
            c.create_line(r, r, min(x2, w - r), r, width=h,
                          fill=self.color, capstyle="round")


class App(object):
    def __init__(self, root, autostart=False):
        self.root = root
        self.stats = MemStats()
        self.stats.open()
        self.busy = False
        self._elevating = False
        self._last_top = 0.0

        root.title(APP)
        root.configure(bg=BG)
        W, H = 960, 742
        self._center(W, H)
        root.minsize(W, H)
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
        self._dark_title()

        self._build()
        root.bind("<Return>", lambda e: self.clean(MODE_STD))
        root.bind("<space>", lambda e: self.clean(MODE_STD))
        root.bind("<Escape>", lambda e: root.destroy())

        self.refresh_loop()
        if autostart:
            mode = autostart if autostart in MODE_CN else MODE_STD
            root.after(500, lambda: self.clean(mode))

    def _center(self, w, h):
        self.root.update_idletasks()
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self.root.geometry("%dx%d+%d+%d" % (w, h, (sw - w) // 2, max(0, (sh - h) // 2 - 40)))

    def _dark_title(self):
        try:
            self.root.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            for attr in (20, 19):
                v = ctypes.c_int(1)
                ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(v), 4)
        except Exception:
            pass

    # ---------- 布局 ----------
    def _build(self):
        pad = 30
        wrap = tk.Frame(self.root, bg=BG)
        wrap.pack(fill="both", expand=True, padx=pad, pady=(20, 16))

        head = tk.Frame(wrap, bg=BG)
        head.pack(fill="x")
        tk.Label(head, text="内存整理", bg=BG, fg=TXT,
                 font=("Microsoft YaHei UI", 15, "bold")).pack(side="left")
        tk.Label(head, text="  加强版 " + VER, bg=BG, fg=DIM, font=F_SM).pack(side="left", pady=(5, 0))

        self.badge = tk.Label(head, text="", bg=BG, fg=SUB, font=F_SM, cursor="hand2")
        self.badge.pack(side="right", pady=(3, 0))
        if is_admin():
            self.badge.configure(text="● 管理员权限", fg=FREE)
        else:
            self.badge.configure(text="○ 普通权限 · 点此提权", fg=STANDBY)
            self.badge.bind("<Button-1>", lambda e: self.relaunch_admin())

        tk.Frame(wrap, bg=CARD2, height=1).pack(fill="x", pady=(14, 20))

        body = tk.Frame(wrap, bg=BG)
        body.pack(fill="x")

        # 左：三条度量
        left = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 18))
        self.m_used = Metric(left, "已用内存", "程序与系统正在占用的，清不掉", USED)
        self.m_used.pack(fill="x", pady=(0, 16))
        self.m_cache = Metric(left, "系统缓存", "Windows 拿来加速的，随时可回收", STANDBY)
        self.m_cache.pack(fill="x", pady=(0, 16))
        self.m_free = Metric(left, "纯空闲", "新程序启动能立刻拿到的", FREE)
        self.m_free.pack(fill="x")

        tk.Label(left, text="任务管理器里的「可用内存」= 系统缓存 + 纯空闲",
                 bg=BG, fg=DIM, font=F_TINY).pack(anchor="w", pady=(16, 0))

        # 右：谁在占内存
        right = tk.Frame(body, bg=CARD, width=286)
        right.pack(side="right", fill="y", padx=(26, 0))
        right.pack_propagate(False)
        tk.Label(right, text="谁在占内存", bg=CARD, fg=SUB, font=F_SM).pack(anchor="w", padx=16, pady=(14, 10))
        self.top_rows = []
        for i in range(5):
            row = tk.Frame(right, bg=CARD)
            row.pack(fill="x", padx=16, pady=(0, 9))
            nm = tk.Label(row, text="—", bg=CARD, fg=TXT, font=F_SM, anchor="w")
            nm.pack(side="left")
            vl = tk.Label(row, text="", bg=CARD, fg=DIM, font=("Consolas", 9))
            vl.pack(side="right")
            bar = tk.Canvas(row, height=3, bg=CARD, highlightthickness=0)
            bar.pack(fill="x")
            self.top_rows.append((nm, vl, bar))

        tk.Label(wrap, text="只清缓存，不结束任何进程。整理前会自动跳过你正在用的窗口。",
                 bg=BG, fg=DIM, font=F_TINY).pack(anchor="w", pady=(18, 0))

        # 按钮区
        bt = tk.Frame(wrap, bg=BG)
        bt.pack(fill="x", pady=(18, 0))
        row = tk.Frame(bt, bg=BG)
        row.pack()
        self.btn_main = Btn(row, "一键整理", lambda: self.clean(MODE_STD), primary=True, size=F_BTN)
        self.btn_main.pack(side="left", padx=(0, 10))
        self.btn_light = Btn(row, "轻度", lambda: self.clean(MODE_LIGHT))
        self.btn_light.pack(side="left", padx=5)
        self.btn_deep = Btn(row, "深度", lambda: self.clean(MODE_DEEP))
        self.btn_deep.pack(side="left", padx=5)

        self.hint = tk.Label(bt, text="标准：清缓存 + 整理后台　|　轻度：只清缓存　|　深度：连后台窗口一起压",
                             bg=BG, fg=DIM, font=F_TINY)
        self.hint.pack(pady=(10, 0))

        self.result = tk.Label(wrap, text=self._last_summary(), bg=BG, fg=SUB,
                               font=F_UI, wraplength=880, justify="center")
        self.result.pack(pady=(16, 0))

        box = tk.Frame(wrap, bg=CARD)
        box.pack(fill="both", expand=True, pady=(12, 0))
        self.log = tk.Text(box, bg=CARD, fg=SUB, font=("Consolas", 9),
                           relief="flat", bd=0, padx=16, pady=10,
                           insertbackground=BG, wrap="char", height=7)
        self.log.pack(fill="both", expand=True)
        self.log.tag_configure("ok", foreground=FREE)
        self.log.tag_configure("warn", foreground=STANDBY)
        self.log.tag_configure("err", foreground=USED)
        self.log.tag_configure("dim", foreground=DIM)
        self._log("就绪。等待命缓存攒多再清，效果最明显。", "dim")

    def _last_summary(self):
        try:
            with open(LOGFILE, "r", encoding="utf-8") as f:
                lines = [l for l in f if l.strip()]
            if not lines:
                return "点一键整理开始。"
            last = lines[-1]
            parts = [p.strip() for p in last.split("|")]
            # 日志首列是完整的 "YYYY-mm-dd HH:MM:SS"，取末 5 位会得到 "34:56"。
            try:
                when = datetime.datetime.strptime(parts[0], "%Y-%m-%d %H:%M:%S").strftime("%m-%d %H:%M")
            except (ValueError, IndexError):
                when = parts[0][:16] if parts else ""
            gain = ""
            for p in parts:
                if p.startswith("空闲") and "(" in p:
                    gain = p[p.rfind("(") + 1:].rstrip(")")
            if gain:
                return "上次整理 %s · 让出 %s" % (when, gain)
        except Exception:
            pass
        return "点一键整理开始。"

    # ---------- 刷新 ----------
    def refresh_loop(self):
        if not self.busy:
            try:
                self.stats.refresh()
                self.paint()
            except Exception:
                pass
        self.root.after(1200, self.refresh_loop)

    def paint(self):
        s = self.stats
        total = max(1, s.total)
        self.m_used.set(s.used, total)
        self.m_cache.set(s.standby, total)
        self.m_free.set(s.free_zero, total)

        now = time.time()
        if now - self._last_top > 5:
            self._last_top = now
            self._paint_top()

    def _paint_top(self):
        try:
            items = top_processes(5)
        except Exception:
            return
        top = items[0][1] if items else 1
        for i, (nm, vl, bar) in enumerate(self.top_rows):
            if i < len(items):
                name, val = items[i]
                nm.configure(text=name[:14])
                vl.configure(text=gb(val))
                bar.delete("all")
                w = bar.winfo_width() or 1
                ratio = max(0.02, val / float(top))
                bar.create_line(1.5, 1.5, max(2, w * ratio), 1.5, width=3,
                                fill=USED if i == 0 else "#39404E", capstyle="round")
            else:
                nm.configure(text="—")
                vl.configure(text="")
                bar.delete("all")

    # ---------- 动作 ----------
    def _log(self, text, tag=None):
        self.log.insert("end", text + "\n", tag)
        self.log.see("end")
        self.log.yview_moveto(1.0)

    def relaunch_admin(self, mode=MODE_STD):
        """脚本模式下才用得到。exe 由 --uac-admin 在启动时提权，不会走这里。"""
        if self._elevating:
            return
        if mode not in MODE_CN:
            mode = MODE_STD
        self._elevating = True
        try:
            for k in ("_PYI_APPLICATION_HOME_DIR", "_PYI_PARENT_PROCESS_LEVEL",
                      "_PYI_ARCHIVE_FILE", "_MEIPASS2"):
                os.environ.pop(k, None)
            if getattr(sys, "frozen", False):
                target, params = sys.executable, "--autostart=%s" % mode
            else:
                target = sys.executable
                params = '"%s" --autostart=%s' % (os.path.abspath(__file__), mode)

            sh = ctypes.WinDLL("shell32", use_last_error=True)
            sh.ShellExecuteW.restype = ctypes.c_void_p
            sh.ShellExecuteW.argtypes = [wt.HWND, wt.LPCWSTR, wt.LPCWSTR,
                                         wt.LPCWSTR, wt.LPCWSTR, ctypes.c_int]
            ret = sh.ShellExecuteW(None, "runas", target, params, BASE, 1)
            code = int(ret) if ret else 0
            if code <= 32:
                raise OSError(self._shell_reason(code))
            self.result.configure(text="正在以管理员身份重新启动…", fg=SUB)
            self.root.after(1500, self.root.destroy)
        except Exception as e:
            # 关键：失败时窗口必须留着，不能让用户面对"闪一下就没了"
            self._elevating = False
            self.result.configure(text="提权失败：%s。窗口已保留，可用普通权限继续。" % e, fg=USED)
            self._log("提权失败：%s" % e, "err")

    @staticmethod
    def _shell_reason(code):
        return {
            0: "系统资源不足",
            2: "找不到文件",
            3: "找不到路径",
            5: "访问被拒绝（UAC 被取消？）",
            8: "内存不足",
            26: "共享冲突",
            27: "文件关联不完整",
            28: "DDE 超时",
            29: "DDE 失败",
            30: "DDE 忙",
            31: "没有关联的应用",
            32: "不支持的 ShellExecute 版本",
        }.get(code, "错误码 %d" % code)

    def clean(self, mode):
        if self.busy:
            return
        if not is_admin():
            self.result.configure(text="清待命列表需要管理员权限。点右上角提权后会自动开始整理。", fg=STANDBY)
            self.relaunch_admin(mode)
            return

        self.busy = True
        self.btn_main.set_enabled(False)
        self.btn_light.set_enabled(False)
        self.btn_deep.set_enabled(False)
        self.btn_main.set_text("整理中…")
        self.result.configure(text="正在整理……", fg=STANDBY)
        self.log.delete("1.0", "end")

        def work():
            try:
                res = run_clean(mode, self.stats,
                                on_log=lambda s, t=None: self.root.after(
                                    0, lambda x=s, y=t: self._log(x, y or "dim")))
                self.root.after(0, lambda: self.done(res))
            except Exception as e:
                # 异常变量在 except 结束时会被删除；这里用默认参数立刻绑住，
                # 否则 after 回调真正执行时 e 已不存在，失败界面永远不出现。
                self.root.after(0, lambda err=e: self.fail(err))

        threading.Thread(target=work, daemon=True).start()

    def fail(self, e):
        self.busy = False
        self.btn_main.set_enabled(True)
        self.btn_light.set_enabled(True)
        self.btn_deep.set_enabled(True)
        self.btn_main.set_text("一键整理")
        self.result.configure(text="出错了：%s" % e, fg=USED)
        self._log("异常：%s" % e, "err")

    def done(self, r):
        self.busy = False
        self.btn_main.set_enabled(True)
        self.btn_light.set_enabled(True)
        self.btn_deep.set_enabled(True)
        self.btn_main.set_text("一键整理")

        b, a = r.before, r.after
        gain = max(0, a.free_zero - b.free_zero)
        used_drop = max(0, b.used - a.used)
        stb_drop = max(0, b.standby - a.standby)

        if not r.purged:
            self.result.configure(
                text="没能真正腾出物理内存：页面只是从「已用」搬到了「缓存」。以管理员身份运行才能清待命列表。",
                fg=STANDBY)
        elif gain > 0:
            self.result.configure(
                text="让出 %s —— 纯空闲 %s → %s，耗时 %.1f 秒" % (gb(gain), gb(b.free_zero), gb(a.free_zero), r.elapsed),
                fg=FREE)
        else:
            self.result.configure(
                text="纯空闲没有变化 —— 本来就不缺可用内存，这次清了也白清", fg=SUB)

        self._log("已用      %s → %s（-%s）" % (gb(b.used), gb(a.used), gb(used_drop)), "dim")
        self._log("系统缓存  %s → %s（-%s）" % (gb(b.standby), gb(a.standby), gb(stb_drop)), "dim")
        self._log("纯空闲    %s → %s（+%s）" % (gb(b.free_zero), gb(a.free_zero), gb(gain)), "ok")

        self.stats.refresh()
        self.paint()
        self._last_top = 0
        self.write_log(r, gain)

    def write_log(self, r, gain):
        try:
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(LOGFILE, "a", encoding="utf-8") as f:
                f.write("%s | %-4s | 空闲 %s -> %s (+%s) | 压缩 %d 个进程 %.0fMB | %.2fs\n"
                        % (ts, MODE_CN[r.mode], gb(r.before.free_zero), gb(r.after.free_zero),
                           gb(gain), r.trim_count, r.trimmed / 1048576.0, r.elapsed))
        except Exception:
            pass


def report_crash(exc_type, exc, tb):
    """--windowed 会吞掉 stderr，所以异常必须自己写到文件 + 弹窗。"""
    txt = "".join(traceback.format_exception(exc_type, exc, tb))
    try:
        with open(ERRFILE, "a", encoding="utf-8") as f:
            f.write("\n[%s] argv=%s admin=%s\n%s\n"
                    % (datetime.datetime.now(), sys.argv, is_admin(), txt))
    except Exception:
        pass
    try:
        last = txt.strip().splitlines()[-1]
        ctypes.windll.user32.MessageBoxW(
            None, "程序遇到错误，已写入 启动错误.log\n\n%s" % last, APP, 0x10)
    except Exception:
        pass


def main():
    # 提权重启要带上用户刚点的模式；旧参数 --autostart 仍按标准模式处理。
    autostart = False
    for arg in sys.argv[1:]:
        if arg.startswith("--autostart="):
            autostart = arg.split("=", 1)[1] or MODE_STD
        elif arg == "--autostart":
            autostart = MODE_STD
    if autostart not in MODE_CN:
        autostart = False
    root = tk.Tk()
    root.report_callback_exception = lambda t, e, tb: report_crash(t, e, tb)
    App(root, autostart=autostart)
    root.mainloop()


if __name__ == "__main__":
    sys.excepthook = report_crash
    try:
        main()
    except Exception:
        report_crash(*sys.exc_info())
        raise
