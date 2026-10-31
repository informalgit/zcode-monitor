# -*- coding: utf-8 -*-
"""ZCode 套餐额度悬浮窗（托盘版）

读取本机 ~/.zcode 的登录凭证，调用 ZCode 官方额度接口，在置顶小浮窗上显示
个人 Coding Plan（GLM token plan）与体验套餐（start-plan）的剩余额度与重置倒计时。

- 系统托盘：图标颜色跟随剩余最少的额度（绿/黄/红），悬停显示各模型百分比，
  左键显示/隐藏浮窗，右键完整菜单（立即刷新 / 重置位置 / 置顶 / 半透明 / 开机自启 / 退出）
- 窗口位置始终钳制在可见工作区内；「重置位置」一键回到默认位置
- 仅用 Python 标准库（tkinter + ctypes），无第三方依赖
"""
import base64
import hashlib
import json
import os
import queue
import struct
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid
import winreg
import tkinter as tk
import ctypes
from ctypes import wintypes

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

HOME = os.path.expanduser("~")
V2_DIR = os.path.join(HOME, ".zcode", "v2")
CONFIG_PATH = os.path.join(V2_DIR, "config.json")
TELEMETRY_PATH = os.path.join(V2_DIR, "telemetry-state.json")
BALANCE_URL = "https://zcode.z.ai/api/v1/zcode-plan/billing/balance"
# 个人 Coding Plan 用量接口（与 ZCode 客户端「使用统计」页同源），host 跟随凭证家族
QUOTA_LIMIT_URLS = {
    "bigmodel": "https://open.bigmodel.cn/api/monitor/usage/quota/limit",
    "zai": "https://api.z.ai/api/monitor/usage/quota/limit",
}
# (unit, number) → 显示名：3/5 = 5 小时 Prompt 池，6/1 = 每周额度
LIMIT_LABELS = {(3, 5): "5小时额度", (6, 1): "每周额度"}
APP_TIP = "ZCode 套餐额度"
APP_VER_FALLBACK = "3.11.2"
REFRESH_SECS = 60 # 自动刷新间隔
LOG_PATH = os.path.join(tempfile.gettempdir(), "zcode-quota-widget.log")

# ---------- 凭证 ----------

def app_version() -> str:
    try:
        for hive, path in [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]:
            try:
                key = winreg.OpenKey(hive, path)
            except OSError:
                continue
            with key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
                    except OSError:
                        continue
                    with sub:
                        name = ver = ""
                        for j in range(winreg.QueryInfoKey(sub)[1]):
                            vn, val, _ = winreg.EnumValue(sub, j)
                            if vn == "DisplayName":
                                name = str(val)
                            elif vn == "DisplayVersion":
                                ver = str(val)
                        if "zcode" in name.lower() and "switch" not in name.lower() and ver:
                            return ver
    except Exception:
        pass
    return APP_VER_FALLBACK


def os_version() -> str:
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        with key:
            build, _ = winreg.QueryValueEx(key, "CurrentBuildNumber")
        return f"10.0.{build}"
    except Exception:
        return "10.0.19045"


def device_mid() -> str | None:
    try:
        with open(TELEMETRY_PATH, encoding="utf-8") as f:
            return json.load(f).get("deviceMid")
    except Exception:
        return None


def _decrypt_enc_v1(value: str) -> str:
    """解密 ZCode 凭据的 enc:v1 格式（AES-256-GCM，纯 Python 实现，见 pure_gcm.py）。"""
    from pure_gcm import gcm_decrypt
    secret = f"zcode-credential-fallback:win32:{HOME}:{os.environ.get('USERNAME', '')}"
    key = hashlib.sha256(secret.encode()).digest()
    dec64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    n_b, t_b, c_b = value[len("enc:v1:"):].split(".")
    return gcm_decrypt(key, dec64(n_b), dec64(c_b), dec64(t_b)).decode("utf-8")


def load_token() -> tuple[str, str]:
    """返回 (token, provider_id)。优先 credentials.json 的活跃登录 JWT（新版 ZCode
    已把令牌加密存到那里；config.json 里的 start-plan apiKey 只是过期副本）。"""
    cred_path = os.path.join(V2_DIR, "credentials.json")
    if os.path.exists(cred_path):
        try:
            with open(cred_path, encoding="utf-8") as f:
                enc = json.load(f).get("zcodejwttoken") or ""
            if enc.startswith("enc:v1:"):
                return _decrypt_enc_v1(enc), "credentials:zcodejwttoken"
            if enc.startswith("eyJ") and len(enc) > 40:
                return enc, "credentials:zcodejwttoken"
        except Exception:
            pass  # 解密失败（密钥变化等）则回退到 config.json
    with open(CONFIG_PATH, encoding="utf-8") as f:
        cfg = json.load(f)
    providers = cfg.get("provider") or {}
    ordered = sorted(
        providers.items(),
        key=lambda kv: 0 if (kv[1] or {}).get("enabled") else 1)
    for pid, p in ordered:
        if "start-plan" not in pid:
            continue
        key = ((p or {}).get("options") or {}).get("apiKey") or ""
        if key and not key.startswith("enc:") and len(key) > 20:
            return key, pid
    raise RuntimeError("未找到可用的登录凭证（credentials.json / config.json）")


def load_coding_plan_candidates() -> list[tuple[str, str, str]]:
    """返回 [(family, token, url)]：个人 Coding Plan 的额度查询凭证，按优先级排序。

    新版 ZCode 把 OAuth access_token 与套餐 api-key 加密存在 credentials.json；
    oauth:active_provider 决定优先家族（bigmodel → open.bigmodel.cn，zai → api.z.ai）。
    """
    cred_path = os.path.join(V2_DIR, "credentials.json")
    if not os.path.exists(cred_path):
        return []
    try:
        with open(cred_path, encoding="utf-8") as f:
            creds = json.load(f)
    except Exception:
        return []
    active = ""
    val = creds.get("oauth:active_provider")
    if isinstance(val, str) and val.startswith("enc:v1:"):
        try:
            active = _decrypt_enc_v1(val).strip().lower()
        except Exception:
            pass
    families = ["bigmodel", "zai"]
    if active == "zai":
        families.reverse()
    out: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for fam in families:
        tokens = []
        val = creds.get(f"oauth:{fam}:access_token")
        if isinstance(val, str):
            tokens.append(val)
        for k, v in creds.items():
            if (isinstance(k, str) and isinstance(v, str)
                    and k.startswith("account-provider:coding-plan:account:")
                    and k.endswith(":api-key") and f":{fam}-" in k):
                tokens.append(v)
        for enc in tokens:
            if not enc.startswith("enc:v1:"):
                continue
            try:
                tok = _decrypt_enc_v1(enc)
            except Exception:
                continue
            if tok and (fam, tok) not in seen:
                seen.add((fam, tok))
                out.append((fam, tok, QUOTA_LIMIT_URLS[fam]))
    return out


# ---------- 接口 ----------

def client_timezone() -> str:
    tz = time.tzname[0] or ""
    try:
        tz.encode("latin-1")  # HTTP 头不允许非 ASCII（中文系统会返回“中国标准时间”）
    except UnicodeEncodeError:
        return "Asia/Shanghai"
    return tz


def fetch_quota(token: str) -> dict:
    ver = app_version()
    headers = {
        "User-Agent": f"ZCode/{ver}",
        "HTTP-Referer": "https://zcode.z.ai",
        "X-Title": "Z Code@electron",
        "X-ZCode-App-Version": ver,
        "X-Platform": "win32-x64",
        "X-Release-Channel": "stable",
        "X-Client-Language": "zh-CN",
        "X-Client-Timezone": client_timezone(),
        "X-Os-Category": "windows",
        "X-Os-Version": os_version(),
        "Authorization": f"Bearer {token}",
        "x-request-id": str(uuid.uuid4()),
        "Accept": "application/json",
    }
    mid = device_mid()
    if mid:
        headers["X-Device-Mid"] = mid
    req = urllib.request.Request(f"{BALANCE_URL}?app_version={ver}", headers=headers)
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    if payload.get("code") not in (0, None):
        msg = payload.get("msg") or payload.get("message") or str(payload.get("code"))
        raise RuntimeError(f"接口返回错误：{msg}")
    return payload.get("data") or {}


def fetch_coding_plan(token: str, url: str) -> dict:
    """个人 Coding Plan 用量：GET /api/monitor/usage/quota/limit，头为小写 authorization。"""
    headers = {
        "authorization": token,
        "Accept": "application/json",
        "User-Agent": f"ZCode/{app_version()}",
        "x-request-id": str(uuid.uuid4()),
        "X-Client-Timezone": client_timezone(),
    }
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    if payload.get("success") is False or payload.get("code") not in (0, 200, None):
        msg = payload.get("msg") or payload.get("message") or str(payload.get("code"))
        raise RuntimeError(f"接口返回错误：{msg}")
    return payload.get("data") or {}


def parse_quota(data: dict) -> list[dict]:
    """解析为 [{name, buckets: [{model, total, remaining, pct, period_end, daily}]}]"""
    plans = {p.get("user_plan_id"): p for p in data.get("plans") or []}
    periods = {}
    for p in plans.values():
        for ent in p.get("entitlements") or []:
            periods[(p.get("user_plan_id"), ent.get("entitlement_id"))] = ent.get("period")

    groups: dict[str, dict] = {}
    for b in data.get("balances") or []:
        upid = b.get("user_plan_id", "")
        plan = plans.get(upid, {})
        gkey = upid or b.get("plan_id", "?")
        g = groups.setdefault(gkey, {
            "name": plan.get("name") or b.get("plan_id") or "套餐",
            "priority": plan.get("priority") or 0,
            "buckets": [],
        })
        total = b.get("total_units")
        remaining = b.get("available_units")
        if remaining is None:
            remaining = b.get("remaining_units")
        pct = (remaining / total * 100.0) if isinstance(total, (int, float)) and total > 0 else None
        g["buckets"].append({
            "model": b.get("show_name") or b.get("entitlement_id") or "?",
            "total": total,
            "remaining": remaining,
            "pct": pct,
            "period_end": b.get("expires_at") or b.get("period_end"),
            "daily": periods.get((upid, b.get("entitlement_id"))) == "daily",
        })
    return sorted(groups.values(), key=lambda g: -g["priority"])


def parse_coding_plan(data: dict, family: str) -> list[dict]:
    """monitor/quota/limit 响应 → 与体验套餐相同的 groups 结构。

    limits 里每项是一个额度窗口（unit=3/number=5 为 5 小时池，unit=6/number=1 为每周）；
    usage=总量，remaining=剩余，nextResetTime=毫秒时间戳。
    """
    level = (data.get("level") or "").strip() if isinstance(data, dict) else ""
    label = "GLM Coding Plan" + (f" · {level}" if level else "")
    buckets = []
    for lim in (data or {}).get("limits") or []:
        if not isinstance(lim, dict):
            continue
        total, remaining = lim.get("usage"), lim.get("remaining")
        pct = (remaining / total * 100.0 if isinstance(total, (int, float)) and total > 0
               and isinstance(remaining, (int, float)) else None)
        reset = lim.get("nextResetTime")
        if isinstance(reset, (int, float)) and reset > 1e12:
            reset /= 1000.0  # 毫秒 → 秒
        buckets.append({
            "model": LIMIT_LABELS.get((lim.get("unit"), lim.get("number")), "套餐额度"),
            "total": total,
            "remaining": remaining,
            "pct": pct,
            "period_end": reset,
            "daily": True,
        })
    return [{"name": label, "priority": 10, "buckets": buckets}] if buckets else []


# ---------- 格式化 ----------

def fmt_tok(n) -> str:
    if not isinstance(n, (int, float)):
        return "?"
    a = abs(n)
    if a >= 1e8:
        return f"{n / 1e8:.2f} 亿"
    if a >= 1e4:
        return f"{n / 1e4:.0f} 万"
    return f"{n:,.0f}"


def fmt_countdown(ts) -> str:
    if not isinstance(ts, (int, float)):
        return ""
    d = ts - time.time()
    if d <= 0:
        return "即将重置"
    h = int(d // 3600)
    m = int(d % 3600 // 60)
    if h >= 24:
        return f"{h // 24}天{h % 24}小时后"
    if h >= 1:
        return f"{h}小时{m}分后"
    return f"{m}分钟后"


def short_model(name: str) -> str:
    return name.replace("GLM-", "").replace("-Flash", "F")


def summary_text(groups: list[dict]) -> str:
    parts = []
    for g in groups:
        for b in g["buckets"]:
            pct = b["pct"]
            parts.append(f"{short_model(b['model'])} {pct:.0f}%" if pct is not None
                         else f"{short_model(b['model'])} —")
    return " / ".join(parts)


# ---------- Win32 托盘 ----------

user32 = ctypes.WinDLL("user32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT,
                             wintypes.WPARAM, wintypes.LPARAM)
user32.DefWindowProcW.restype = LRESULT
user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.CreateWindowExW.restype = wintypes.HWND
user32.LoadImageW.restype = wintypes.HANDLE
user32.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT,
                              ctypes.c_int, ctypes.c_int, wintypes.UINT]
user32.LoadIconW.restype = wintypes.HANDLE
user32.LoadIconW.argtypes = [wintypes.HINSTANCE, ctypes.c_void_p]
user32.DestroyIcon.argtypes = [wintypes.HICON]
shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.c_void_p]
user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
user32.TrackPopupMenu.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int,
                                  ctypes.c_int, wintypes.HWND, ctypes.c_void_p]
user32.TrackPopupMenu.restype = wintypes.BOOL
user32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR]
user32.SystemParametersInfoW.argtypes = [wintypes.UINT, wintypes.UINT, ctypes.c_void_p, wintypes.UINT]
user32.FindWindowW.restype = wintypes.HWND
user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
user32.PostMessageW.restype = wintypes.BOOL
user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
kernel32.CreateMutexW.restype = wintypes.HANDLE
kernel32.CreateMutexW.argtypes = [wintypes.HANDLE, wintypes.BOOL, wintypes.LPCWSTR]


class WNDCLASSW(ctypes.Structure):
    _fields_ = [("style", wintypes.UINT), ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON),
                ("hCursor", ctypes.c_void_p), ("hbrBackground", wintypes.HBRUSH),
                ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR)]


class NID(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND), ("uID", wintypes.UINT),
                ("uFlags", wintypes.UINT), ("uCallbackMessage", wintypes.UINT),
                ("hIcon", wintypes.HICON), ("szTip", wintypes.WCHAR * 128),
                ("dwState", wintypes.DWORD), ("dwStateMask", wintypes.DWORD),
                ("szInfo", wintypes.WCHAR * 256), ("uVersion", wintypes.UINT),
                ("szInfoTitle", wintypes.WCHAR * 64), ("dwInfoFlags", wintypes.DWORD)]


class RECT(ctypes.Structure):
    _fields_ = [("left", wintypes.LONG), ("top", wintypes.LONG),
                ("right", wintypes.LONG), ("bottom", wintypes.LONG)]


NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP = 1, 2, 4
WM_APP_TRAY = 0x8000
WM_LBUTTONUP, WM_RBUTTONUP = 0x0202, 0x0205
WM_CLOSE = 0x0010
ERROR_ALREADY_EXISTS = 183
IMAGE_ICON, LR_LOADFROMFILE = 1, 0x10
SPI_GETWORKAREA = 0x0030
MF_SEPARATOR, MF_CHECKED = 0x800, 0x8
TPM_RIGHTBUTTON, TPM_RETURNCMD = 0x2, 0x100
HWND_MESSAGE = wintypes.HWND(-3)
HWND_TOPMOST = wintypes.HWND(-1)
GA_ROOT = 2
GW_HWNDPREV = 3
GWL_EXSTYLE = -20
WS_EX_TOPMOST = 0x00000008
SWP_NOSIZE, SWP_NOMOVE, SWP_NOACTIVATE, SWP_SHOWWINDOW = 0x0001, 0x0002, 0x0010, 0x0040

user32.GetAncestor.restype = wintypes.HWND
user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
user32.IsWindow.restype = wintypes.BOOL
user32.IsWindow.argtypes = [wintypes.HWND]
user32.SetWindowPos.restype = wintypes.BOOL
user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                                ctypes.c_int, ctypes.c_int, wintypes.UINT]
user32.GetWindow.restype = wintypes.HWND
user32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(RECT)]
user32.IsWindowVisible.argtypes = [wintypes.HWND]
_GetWindowLongPtrW = getattr(user32, "GetWindowLongPtrW", None)
if _GetWindowLongPtrW is not None:
    _GetWindowLongPtrW.restype = ctypes.c_ssize_t
    _GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]


def _get_ex_style(hwnd: int) -> int:
    if _GetWindowLongPtrW is not None:
        return int(_GetWindowLongPtrW(hwnd, GWL_EXSTYLE)) & 0xFFFFFFFF
    return int(user32.GetWindowLongW(hwnd, GWL_EXSTYLE)) & 0xFFFFFFFF

# 托盘 / 窗口右键菜单共用命令 id
CMD_TOGGLE_SHOW, CMD_RESET_POS, CMD_REFRESH, CMD_TOPMOST, CMD_ALPHA, CMD_AUTOSTART, CMD_QUIT = \
    1, 2, 3, 4, 5, 6, 9


def make_ico_bytes(rgb: tuple[int, int, int]) -> bytes:
    """生成 16x16 32bpp 图标：纯色圆盘 + 白色闪电，透明四角。"""
    size = 16
    bolt = set()
    for i in range(7):          # 上半段斜杠
        for dx in range(3):
            bolt.add((8 - i + dx, 2 + i))
    for i in range(5):          # 下半段细尾
        for dx in range(2):
            bolt.add((7 - i + dx, 9 + i))

    r, g, b = rgb
    xor = bytearray()
    for y in range(size - 1, -1, -1):     # 自底向上
        for x in range(size):
            dx, dy = x - 7.5, y - 7.5
            if dx * dx + dy * dy <= 45.0:
                if (x, y) in bolt:
                    xor += bytes((255, 255, 255, 255))
                else:
                    xor += bytes((b, g, r, 255))
            else:
                xor += bytes((0, 0, 0, 0))
    and_mask = bytes(size * 4)            # 16 行 x 4 字节，全 0
    bmp = (struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0,
                       len(xor) + len(and_mask), 0, 0, 0, 0)
           + bytes(xor) + and_mask)
    ico = (struct.pack("<HHH", 0, 1, 1)
           + struct.pack("<BBBBHHII", size, size, 0, 0, 1, 32, len(bmp), 22)
           + bmp)
    return ico


def autostart_enabled() -> bool:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Run")
        with key:
            winreg.QueryValueEx(key, "ZCodeQuotaWidget")
        return True
    except OSError:
        return False


# ---------- 单实例 ----------

SINGLE_MUTEX = "Local\\ZCodeQuotaWidgetSingleInstance"
# 旧版本的窗口标题：接管时一并向它们发送关闭消息
LEGACY_TITLES = (APP_TIP, "ZCode 体验套餐额度")
_MUTEX_HANDLE = None


def _post_close_all() -> bool:
    """向所有浮窗窗口发 WM_CLOSE（走 Tk 退出协议，托盘图标一并清理）。

    返回是否找到了窗口；同名窗口逐个关闭，设上限防死循环。"""
    found = False
    for title in LEGACY_TITLES:
        for _ in range(20):
            hwnd = user32.FindWindowW(None, title)
            if not hwnd:
                break
            found = True
            user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
            time.sleep(0.15)
    return found


def acquire_single_instance(timeout: float = 6.0) -> bool:
    """保证全局只有一个浮窗：先请求已运行的实例退出，再持有互斥锁。

    新实例持有互斥锁，其窗口可通过标题找到并优雅关闭；旧版本没有锁，
    只能按窗口标题接管。接管失败（对方假死）返回 False。"""
    global _MUTEX_HANDLE
    deadline = time.time() + timeout
    while True:
        _MUTEX_HANDLE = kernel32.CreateMutexW(None, False, SINGLE_MUTEX)
        if _MUTEX_HANDLE and ctypes.get_last_error() != ERROR_ALREADY_EXISTS:
            break
        _post_close_all()
        if time.time() >= deadline:
            return False
        time.sleep(0.25)
    for _ in range(20):  # 旧版本不持锁，拿到锁后再清扫一遍残留窗口
        if not _post_close_all():
            break
        time.sleep(0.25)
    return True


class Tray:
    """系统托盘图标：独立线程内建 message-only 窗口接收回调。"""

    def __init__(self, widget):
        self.widget = widget
        self.hwnd = None
        self.hicon = None
        self._color_key = None
        self._added = False
        self._wndproc_ref = WNDPROC(self._wndproc)

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        hinst = kernel32.GetModuleHandleW(None)
        cls = WNDCLASSW()
        cls.lpfnWndProc = self._wndproc_ref
        cls.hInstance = hinst
        cls.lpszClassName = "ZQuotaWidgetTray"
        if not user32.RegisterClassW(ctypes.byref(cls)):
            return
        self.hwnd = user32.CreateWindowExW(
            0, "ZQuotaWidgetTray", "ZQuotaWidgetTray", 0,
            0, 0, 0, 0, HWND_MESSAGE, None, hinst, None)
        if not self.hwnd:
            return
        self.update_icon("gray", APP_TIP + " · 启动中")
        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

    def _load_hicon(self, color_key, rgb):
        path = os.path.join(tempfile.gettempdir(), f"zqw_{color_key}.ico")
        try:
            with open(path, "wb") as f:
                f.write(make_ico_bytes(rgb))
        except OSError:
            return user32.LoadIconW(None, 32512)  # IDI_APPLICATION
        return user32.LoadImageW(None, path, IMAGE_ICON, 0, 0, LR_LOADFROMFILE)

    def update_icon(self, color_key: str, tip: str):
        """颜色变化时重建图标；每次刷新更新悬停文字。线程安全。"""
        if not self.hwnd:
            return
        rgb = {"green": (74, 222, 128), "amber": (251, 191, 36),
               "red": (248, 113, 113), "gray": (154, 160, 166)}[color_key]
        nid = NID()
        nid.cbSize = ctypes.sizeof(nid)
        nid.hWnd = self.hwnd
        nid.uID = 1
        nid.uCallbackMessage = WM_APP_TRAY
        nid.szTip = tip[:127]
        old = None
        if color_key != self._color_key:
            new_icon = self._load_hicon(color_key, rgb)
            if new_icon:
                nid.hIcon = new_icon
                nid.uFlags = NIF_MESSAGE | NIF_TIP | NIF_ICON
                old, self.hicon, self._color_key = self.hicon, new_icon, color_key
            else:
                nid.uFlags = NIF_MESSAGE | NIF_TIP
        else:
            nid.uFlags = NIF_MESSAGE | NIF_TIP
        if nid.hIcon is None and self.hicon:
            nid.hIcon = self.hicon
            nid.uFlags |= NIF_ICON
        if self._added:
            shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))
        else:
            shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))
            self._added = True
        if old:
            user32.DestroyIcon(old)

    def remove(self):
        if self.hwnd and self._added:
            nid = NID()
            nid.cbSize = ctypes.sizeof(nid)
            nid.hWnd = self.hwnd
            nid.uID = 1
            shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
            self._added = False

    def _wndproc(self, hwnd, msg, wp, lp):
        if msg == WM_APP_TRAY:
            m = lp & 0xFFFF
            if m == WM_LBUTTONUP:
                self.widget.q.put(("cmd", CMD_TOGGLE_SHOW))
            elif m == WM_RBUTTONUP:
                self._popup_menu()
            return 0
        return user32.DefWindowProcW(hwnd, msg, wp, lp)

    def _popup_menu(self):
        w = self.widget
        hmenu = user32.CreatePopupMenu()

        def item(cmd, text, checked=False):
            flags = MF_CHECKED if checked else 0
            user32.AppendMenuW(hmenu, flags, cmd, text)

        item(CMD_TOGGLE_SHOW, "显示 / 隐藏浮窗")
        item(CMD_RESET_POS, "重置位置")
        user32.AppendMenuW(hmenu, MF_SEPARATOR, 0, None)
        item(CMD_REFRESH, "立即刷新")
        item(CMD_TOPMOST, "窗口置顶", w.topmost)
        item(CMD_ALPHA, "半透明", w.alpha)
        item(CMD_AUTOSTART, "开机自启", autostart_enabled())
        user32.AppendMenuW(hmenu, MF_SEPARATOR, 0, None)
        item(CMD_QUIT, "退出")
        pt = wintypes.POINT()
        user32.GetCursorPos(ctypes.byref(pt))
        user32.SetForegroundWindow(self.hwnd)  # 保证点击外部时菜单关闭
        cmd = user32.TrackPopupMenu(hmenu, TPM_RIGHTBUTTON | TPM_RETURNCMD,
                                    pt.x, pt.y, 0, self.hwnd, None)
        user32.DestroyMenu(hmenu)
        if cmd:
            self.widget.q.put(("cmd", cmd))


# ---------- UI ----------

BG = "#17181c"
CARD = "#212329"
BORDER = "#2f323a"
TEXT = "#e8e8ea"
SUB = "#9aa0a6"
GREEN = "#4ade80"
AMBER = "#fbbf24"
RED = "#f87171"
FONT = "Microsoft YaHei UI"
W = 300


def pct_color(pct) -> str:
    if pct is None:
        return SUB
    if pct >= 50:
        return GREEN
    if pct >= 20:
        return AMBER
    return RED


class Widget:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.q: queue.Queue = queue.Queue()
        self.wake = threading.Event()
        self.err: str | None = None
        self.groups: list[dict] = []
        self._sig = None       # 上次渲染的数据签名，仅数据变化时重绘，避免闪动
        self.topmost = True
        self.alpha = True
        self.hidden = False
        self.hwnd: int | None = None   # 顶层窗口句柄（winfo_id 是 TkChild，需取 GA_ROOT）

        root.title(APP_TIP)
        root.overrideredirect(True)
        root.attributes("-topmost", True)
        root.attributes("-alpha", 0.93)
        root.configure(bg=BG)
        x, y = self.default_pos()
        root.geometry(f"{W}x60+{x}+{y}")

        self.body = tk.Frame(root, bg=BG)
        self.body.pack(fill="x", padx=6, pady=6)
        tk.Label(self.body, text="获取中…", font=(FONT, 9), fg=SUB, bg=BG,
                 anchor="w").pack(fill="x")

        root.bind_all("<Button-1>", self._press)
        root.bind_all("<B1-Motion>", self._move)
        root.bind_all("<Button-3>", self._menu)

        self.menu = tk.Menu(root, tearoff=0, font=(FONT, 9))
        self.menu.add_command(label="显示 / 隐藏浮窗",
                              command=lambda: self.handle_cmd(CMD_TOGGLE_SHOW))
        self.menu.add_command(label="重置位置",
                              command=lambda: self.handle_cmd(CMD_RESET_POS))
        self.menu.add_separator()
        self.menu.add_command(label="立即刷新",
                              command=lambda: self.handle_cmd(CMD_REFRESH))
        self.menu.add_command(label="窗口置顶", command=lambda: self.handle_cmd(CMD_TOPMOST))
        self.menu.add_command(label="半透明", command=lambda: self.handle_cmd(CMD_ALPHA))
        self.menu.add_command(label="开机自启", command=lambda: self.handle_cmd(CMD_AUTOSTART))
        self.menu.add_separator()
        self.menu.add_command(label="退出", command=lambda: self.handle_cmd(CMD_QUIT))

        root.protocol("WM_DELETE_WINDOW", lambda: self.handle_cmd(CMD_QUIT))

        self.tray = Tray(self)
        self.tray.start()

        threading.Thread(target=self._worker, daemon=True).start()
        self._poll()

    # --- 位置 ---
    def default_pos(self) -> tuple[int, int]:
        rect = RECT()
        if user32.SystemParametersInfoW(SPI_GETWORKAREA, 0, ctypes.byref(rect), 0):
            left, top, right, bottom = rect.left, rect.top, rect.right, rect.bottom
        else:
            left, top = 0, 0
            right, bottom = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        x = right - W - 24
        y = top + 120
        x = max(left + 8, min(x, right - W - 8))
        y = max(top + 8, min(y, bottom - 80))
        return x, y

    def handle_cmd(self, cmd):
        if cmd == CMD_TOGGLE_SHOW:
            if self.hidden:
                self.hidden = False
                self.root.deiconify()
                self._enforce_topmost()
            else:
                self.hidden = True
                self.root.withdraw()
        elif cmd == CMD_RESET_POS:
            self.hidden = False
            self.root.deiconify()
            x, y = self.default_pos()
            self.root.geometry(f"+{x}+{y}")
            self.root.lift()
            self._enforce_topmost()
        elif cmd == CMD_REFRESH:
            self.wake.set()
        elif cmd == CMD_TOPMOST:
            self.topmost = not self.topmost
            self.root.attributes("-topmost", self.topmost)
        elif cmd == CMD_ALPHA:
            self.alpha = not self.alpha
            self.root.attributes("-alpha", 0.93 if self.alpha else 1.0)
        elif cmd == CMD_AUTOSTART:
            self._toggle_autostart()
        elif cmd == CMD_QUIT:
            self.tray.remove()
            self.root.destroy()

    # --- 拖动 / 菜单 ---
    def _press(self, e):
        self._dx, self._dy = e.x_root - self.root.winfo_x(), e.y_root - self.root.winfo_y()

    def _move(self, e):
        self.root.geometry(f"+{e.x_root - self._dx}+{e.y_root - self._dy}")

    def _menu(self, e):
        try:
            self.menu.tk_popup(e.x_root, e.y_root)
        finally:
            self.menu.grab_release()

    # --- 置顶保持（参考 CodexMini）---
    def _top_hwnd(self) -> int:
        """Tk 顶层 HWND：winfo_id 返回的是 TkChild 子窗口，GA_ROOT 才是真正顶层。

        每次校验缓存确实是顶层窗口（GA_ROOT 指向自身）；窗口映射前解析会
        失败、overrideredirect 变化也会重建 wrapper，故失效时重新解析自愈。"""
        hwnd = self.hwnd
        if not hwnd or not user32.IsWindow(hwnd) \
                or user32.GetAncestor(hwnd, GA_ROOT) != hwnd:
            child = self.root.winfo_id()
            top = user32.GetAncestor(child, GA_ROOT)
            hwnd = self.hwnd = int(top) if top else int(child)
        return hwnd

    @staticmethod
    def _overlaps(a: RECT, b: RECT) -> bool:
        return (a.left < b.right and b.left < a.right
                and a.top < b.bottom and b.top < a.bottom)

    def _covered_by_topmost(self) -> bool:
        """是否被其他置顶窗口盖住：只查我们上方的一小段 z-order。"""
        hwnd = self.hwnd
        if not hwnd:
            return False
        mine, other = RECT(), RECT()
        if not user32.GetWindowRect(hwnd, ctypes.byref(mine)):
            return False
        above = user32.GetWindow(hwnd, GW_HWNDPREV)
        for _ in range(24):
            if not above:
                return False
            if user32.IsWindowVisible(above) and _get_ex_style(above) & WS_EX_TOPMOST \
                    and user32.GetWindowRect(above, ctypes.byref(other)) \
                    and self._overlaps(mine, other):
                return True
            above = user32.GetWindow(above, GW_HWNDPREV)
        return False

    def _enforce_topmost(self):
        """置顶丢失自动修复：样式位被清或被其他置顶窗压住时重新抬到最上层。

        样式在位且未被覆盖时不动，避免闪烁；用户关闭「窗口置顶」时不介入。"""
        try:
            if not self.topmost or self.hidden or self.root.state() == "withdrawn":
                return
            hwnd = self._top_hwnd()
            if _get_ex_style(hwnd) & WS_EX_TOPMOST and not self._covered_by_topmost():
                return
            self.root.attributes("-topmost", True)
            flags = SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE | SWP_SHOWWINDOW
            user32.SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, flags)
        except Exception:
            pass  # 保护 after 链

    # --- 数据线程 ---
    def _fetch_coding_plan_groups(self) -> list[dict]:
        """个人 Coding Plan 额度；无凭证视为未配置（不算错误），逐个凭证尝试。"""
        cands = load_coding_plan_candidates()
        if not cands:
            return []
        last = None
        for _fam, token, url in cands:
            try:
                return parse_coding_plan(fetch_coding_plan(token, url), _fam)
            except Exception as exc:
                last = exc
        raise last or RuntimeError("Coding Plan 额度查询失败")

    def _worker(self):
        while True:
            groups, errs = [], []
            try:
                token, _ = load_token()
                groups += parse_quota(fetch_quota(token))
            except Exception as exc:
                errs.append(str(exc))  # 体验套餐不可用不阻塞 Coding Plan 显示
            try:
                groups += self._fetch_coding_plan_groups()
            except Exception as exc:
                errs.append(str(exc))
            if groups:
                self.q.put(("ok", groups))
            elif errs:
                self.q.put(("err", "；".join(errs)))
            self.wake.wait(REFRESH_SECS if groups else 30)
            self.wake.clear()

    def _poll(self):
        try:
            changed = False
            try:
                while True:
                    kind, payload = self.q.get_nowait()
                    if kind == "ok":
                        self.err = None
                        sig = json.dumps(payload, ensure_ascii=False, sort_keys=True)
                        if sig != self._sig:
                            self._sig, self.groups, changed = sig, payload, True
                            self.tray.update_icon(self._worst_color(payload),
                                                  APP_TIP + "\n" + summary_text(payload))
                    elif kind == "err":
                        if self.err != payload:
                            self.err, changed = payload, True
                            self.tray.update_icon("red", f"{APP_TIP}\n{payload[:100]}")
                    elif kind == "cmd":
                        self.handle_cmd(payload)
            except queue.Empty:
                pass
            if changed:
                self.render()
        except Exception:
            # 保护 after 链：渲染或指令处理中的任何异常都不应令定时器永久中断
            pass
        self._enforce_topmost()  # 每秒巡检一次：置顶丢失/被盖住时静默修复
        self.root.after(1000, self._poll)

    @staticmethod
    def _worst_color(groups: list[dict]) -> str:
        pcts = [b["pct"] for g in groups for b in g["buckets"] if b["pct"] is not None]
        if not pcts:
            return "gray"
        worst = min(pcts)
        if worst >= 50:
            return "green"
        if worst >= 20:
            return "amber"
        return "red"

    # --- 渲染 ---
    def render(self):
        for child in list(self.body.winfo_children()):
            child.destroy()
        # 有旧数据时静默容忍瞬时网络错误（托盘图标已变红提示），只在完全没数据时才显示报错
        if self.err and not self.groups:
            tk.Label(self.body, text="⚠ " + self.err, font=(FONT, 8), fg=RED,
                     bg=BG, wraplength=W - 32, justify="left").pack(anchor="w", pady=2)
        elif not self.groups:
            tk.Label(self.body, text="没有生效中的套餐", font=(FONT, 9),
                     fg=SUB, bg=BG, anchor="w").pack(fill="x")
        card = tk.Frame(self.body, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", pady=2)
        first = True
        for g in self.groups:
            for b in g["buckets"]:
                row = tk.Frame(card, bg=CARD)
                row.pack(fill="x", padx=8, pady=(5, 0) if first else (0, 0))
                first = False
                tk.Label(row, text=b["model"], font=(FONT, 9), fg=TEXT, bg=CARD,
                         anchor="w").pack(side="left")
                tk.Label(row, text=f"{fmt_tok(b['remaining'])} / {fmt_tok(b['total'])}",
                         font=(FONT, 8, "bold"), fg=pct_color(b["pct"]),
                         bg=CARD).pack(side="right")
                row2 = tk.Frame(card, bg=CARD)
                row2.pack(fill="x", padx=8, pady=(1, 4))
                cw = W - 130
                bar = tk.Canvas(row2, width=cw, height=5, bg="#2b2d34",
                                highlightthickness=0)
                bar.pack(side="left", pady=1)
                frac = 0 if b["pct"] is None else max(0.0, min(1.0, b["pct"] / 100.0))
                if frac > 0:
                    bar.create_rectangle(0, 0, max(3, int(cw * frac)), 5,
                                         fill=pct_color(b["pct"]), width=0)
                tail = "重置 " if b["daily"] else "到期 "
                tk.Label(row2, text=tail + fmt_countdown(b["period_end"]),
                         font=(FONT, 7), fg=SUB, bg=CARD,
                         anchor="e").pack(side="right")
        self.root.update_idletasks()
        self.root.geometry(f"{W}x{max(40, self.root.winfo_reqheight())}")

    # --- 开机自启 ---
    def _pythonw(self) -> str:
        exe = sys.executable
        return exe.replace("python.exe", "pythonw.exe") if exe.lower().endswith("python.exe") else exe

    def _toggle_autostart(self):
        run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            if autostart_enabled():
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key, 0,
                                    winreg.KEY_SET_VALUE) as k:
                    winreg.DeleteValue(k, "ZCodeQuotaWidget")
            else:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key, 0,
                                    winreg.KEY_SET_VALUE) as k:
                    script = os.path.abspath(__file__)
                    winreg.SetValueEx(k, "ZCodeQuotaWidget", 0, winreg.REG_SZ,
                                      f'"{self._pythonw()}" "{script}"')
        except OSError as exc:
            self.err = f"自启设置失败：{exc}"
            self.render()


def main():
    try:
        if not acquire_single_instance():
            # 已有实例但无法自动关闭（假死等）：提示后退出，避免开出第二个浮窗
            import tkinter.messagebox as mb
            root = tk.Tk()
            root.withdraw()
            mb.showwarning(APP_TIP, "已有一个额度浮窗在运行且无法自动关闭，"
                                    "请从托盘菜单退出它后再启动。")
            return
        root = tk.Tk()
        Widget(root)
        root.mainloop()
    except Exception:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}]\n{traceback.format_exc()}")
        raise


if __name__ == "__main__":
    main()
