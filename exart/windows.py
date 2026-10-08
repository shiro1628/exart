# -*- coding: utf-8 -*-
"""Windows 수집 모듈.

가능하면 OS 내장 기능만 쓴다: 이벤트 로그 wevtutil, 서명 확인 Get-AuthenticodeSignature,
레지스트리 reg save, 해시는 자체 계산, 파일 탐색은 직접 순회.
잠긴 파일은 일반 복사 → forecopy -f → esentutl /vss 순서로 시도한다.
외부 도구(tools/windows)는 있으면 쓰고 없으면 건너뛴다: winpmem, icat/fls,
forecopy, ShimCacheParser, autorunsc, NirSoft 뷰어.
"""
import csv
import glob
import os
import re

from . import core
from .core import module

OS = "windows"


# ---------------------------------------------------------------- 공통 도우미

def _sysroot():
    return os.environ.get("SystemRoot", r"C:\Windows")


def _sysdrive():
    return os.environ.get("SystemDrive", "C:")


def _sys32(*parts):
    return os.path.join(_sysroot(), "System32", *parts)


def _psq(text):
    """PowerShell 작은따옴표 문자열."""
    return "'" + str(text).replace("'", "''") + "'"


def ps(ctx, name, script, out=None, timeout=1800):
    """스크립트를 결과 폴더 scripts/ 에 남기고 powershell -File 로 실행한다(실행 내용이 증거로 남음)."""
    exe = _sys32("WindowsPowerShell", "v1.0", "powershell.exe")
    if not os.path.exists(exe):
        exe = "powershell.exe"
    body = ("$ErrorActionPreference = 'SilentlyContinue'\r\n"
            "$ProgressPreference = 'SilentlyContinue'\r\n"
            "[Console]::OutputEncoding = [Text.Encoding]::UTF8\r\n" + script.replace("\n", "\r\n"))
    path = ctx.path("scripts/%s.ps1" % name)
    with open(path, "w", encoding="utf-8-sig") as f:      # PS 5.1은 BOM이 있어야 UTF-8로 읽는다
        f.write(body)
    return ctx.run([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                    "-File", path], out or "logs/ps_%s.txt" % name, timeout=timeout)


def export_csv(path):
    return "Export-Csv -NoTypeInformation -Encoding UTF8 -Path %s" % _psq(path)


def read_csv(path):
    rows = []
    try:
        with open(path, encoding="utf-8-sig", errors="replace", newline="") as f:
            for row in csv.DictReader(f):
                rows.append(row)
    except OSError:
        pass
    return rows


def profiles():
    """(SID, 프로필 경로) 목록. 레지스트리 ProfileList 기준, 실패하면 Users 폴더."""
    res = []
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")
        i = 0
        while True:
            try:
                sid = winreg.EnumKey(key, i)
            except OSError:
                break
            i += 1
            try:
                sub = winreg.OpenKey(key, sid)
                path = os.path.expandvars(winreg.QueryValueEx(sub, "ProfileImagePath")[0])
                if os.path.isdir(path):
                    res.append((sid, path))
            except OSError:
                continue
    except Exception:
        pass
    known = set(os.path.normcase(p) for _, p in res)
    for p in glob.glob(os.path.join(_sysdrive() + "\\", "Users", "*")):
        if os.path.isdir(p) and os.path.normcase(p) not in known and not os.path.islink(p):
            res.append((None, p))
    return res


def loaded_user_hives():
    try:
        import winreg
        names, i = [], 0
        while True:
            try:
                names.append(winreg.EnumKey(winreg.HKEY_USERS, i))
            except OSError:
                break
            i += 1
        return names
    except Exception:
        return []


def ntfs_drives():
    """고정 디스크 중 NTFS 드라이브 문자."""
    res = []
    try:
        import ctypes
        import string
        k32 = ctypes.windll.kernel32
        mask = k32.GetLogicalDrives()
        for i, letter in enumerate(string.ascii_uppercase):
            if not mask & (1 << i):
                continue
            root = letter + ":\\"
            if k32.GetDriveTypeW(root) != 3:   # DRIVE_FIXED
                continue
            fs = ctypes.create_unicode_buffer(64)
            if k32.GetVolumeInformationW(root, None, 0, None, None, None, fs, 64) and fs.value.upper() == "NTFS":
                res.append(letter)
    except Exception:
        res = [_sysdrive().rstrip(":\\")]
    return res


def fixed_drives():
    return [d + ":\\" for d in ntfs_drives()]


def copy_locked(ctx, src, category):
    """사용 중이라 잠긴 파일: 일반 복사 → forecopy -f(NTFS 직접 읽기) → esentutl /vss 순서로 시도.
    esentutl /vss 는 볼륨 섀도 사본을 만들며 대상 볼륨에 쓰기 때문에 마지막 수단으로 둔다."""
    e = ctx.copy(src, category, record_failure=False, max_size=0)
    if e.get("status") in ("ok", "skipped", "dry_run") or not os.path.exists(src):
        if e.get("status") == "error":
            ctx._record(e)
        return e
    dest = ctx.path("files/%s/%s" % (category, core.mangle(src)))
    meta = {}
    try:
        meta = core.stat_meta(os.stat(src))
    except OSError:
        pass
    tag = core.safe_component(os.path.basename(src))
    fc = ctx.tool("forecopy.exe", "forecopy_handy.exe")
    if fc:
        d = os.path.dirname(dest)
        produced = os.path.join(d, os.path.basename(src))
        ctx.run([fc, "-f", src, d], "logs/forecopy/%s.txt" % tag)
        if os.path.exists(produced) and os.path.getsize(produced) > 0:
            if os.path.normcase(produced) != os.path.normcase(dest):
                os.replace(produced, dest)
            return ctx.record_external(dest, src, "forecopy", meta=meta)
    esent = _sys32("esentutl.exe")
    if os.path.exists(esent):
        if os.path.exists(dest):
            os.remove(dest)
        rc = ctx.run([esent, "/y", src, "/vss", "/d", dest], "logs/esentutl/%s.txt" % tag)
        if rc == 0 and os.path.exists(dest):
            return ctx.record_external(dest, src, "esentutl-vss", meta=meta)
    ctx._record(e)
    return e


SCRIPT_EXT = re.compile(r"(_jsp\.java|\.(rar|7z|ps1|psm1|vbs|vbe|jse|wsf|hta|bat|cmd|jsp|jspx|asp|aspx"
                        r"|ashx|asmx|php|war|cer|cdx|asa|lnk|scr|pif))$|;\.(jpg|gif|bmp|png)$", re.I)
EXEC_EXT = re.compile(r"\.(exe|dll|sys|scr|com|cpl|ocx|ps1|psm1|vbs|vbe|js|jse|wsf|hta|bat|cmd|msi|lnk)$", re.I)
SWEEP_EXCLUDE = ("WinSxS", "Microsoft.NET", "servicing", "WindowsApps", "node_modules",
                 "SoftwareDistribution", "assembly", "Installer")


def _collect_exec(category):
    def pick(path, st, kind):
        if kind in ("pe", "script") or EXEC_EXT.search(path):
            return category
        return None
    return pick


# ---------------------------------------------------------------- 모듈

@module(OS, "memory", "물리 메모리 덤프 (winpmem, --memory)", level="quick", order=0, admin=True)
def memory(ctx):
    import platform
    is64 = platform.machine().endswith("64")
    names = (["winpmem_mini_x64_rc2.exe", "winpmem_mini_x64.exe", "winpmem64.exe", "go-winpmem_amd64.exe"]
             if is64 else ["winpmem_mini_x86.exe", "winpmem86.exe"])
    tool = ctx.tool(*names)
    if not tool:
        ctx.error("메모리 덤프 도구 없음: tools/windows 에 %s 중 하나를 두세요" % ", ".join(names))
        return
    try:
        import ctypes

        class MEMSTAT(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        ms = MEMSTAT()
        ms.dwLength = ctypes.sizeof(MEMSTAT)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
        free = core.disk_free(ctx.out)
        if free is not None and free < ms.ullTotalPhys * 1.1:
            ctx.error("남은 공간(%.1fGB)이 메모리 크기(%.1fGB)보다 작아 덤프를 건너뜀"
                      % (free / 2.0 ** 30, ms.ullTotalPhys / 2.0 ** 30))
            return
    except Exception:
        pass
    # winpmem64/86.exe 는 winpmem_mini(v4.0.rc1)를 이름만 바꿔 둔 것이라 모두 raw 형식으로 쓴다.
    dest = ctx.path("memory/memory.raw")
    args = [tool, "acquire", dest] if "go-winpmem" in tool.lower() else [tool, dest]
    rc = ctx.run(args, "logs/memory.txt", timeout=4 * 3600)
    if not ctx.dry_run and (not os.path.exists(dest) or os.path.getsize(dest) == 0):
        ctx.error("메모리 덤프 실패(rc=%s) — logs/memory.txt 확인" % rc)
        return
    ctx.record_external(dest, "physical memory", os.path.basename(tool))


@module(OS, "volatile", "프로세스·네트워크·세션 등 휘발성 정보", level="quick", order=10)
def volatile(ctx):
    d = "volatile/"
    cmds = [
        (["ipconfig", "/all"], "ipconfig_all.txt"),
        (["ipconfig", "/displaydns"], "dns_cache.txt"),
        (["arp", "-a"], "arp.txt"),
        (["route", "print"], "route.txt"),
        (["netstat", "-ano"], "netstat_ano.txt"),
        (["netstat", "-anob"], "netstat_anob.txt"),
        (["net", "session"], "net_session.txt"),
        (["net", "use"], "net_use.txt"),
        (["net", "share"], "net_share.txt"),
        (["query", "user"], "logged_on_users.txt"),
        (["whoami", "/all"], "whoami_all.txt"),
        (["tasklist", "/v", "/fo", "csv"], "tasklist_v.csv"),
        (["tasklist", "/svc", "/fo", "csv"], "tasklist_svc.csv"),
        # Stealth Falcon 등은 BITS로 C2 통신·파일 전송을 한다
        (["bitsadmin", "/list", "/allusers", "/verbose"], "bits_jobs.txt"),
        (["netsh", "winhttp", "show", "proxy"], "winhttp_proxy.txt"),
    ]
    for argv, name in cmds:
        ctx.run(argv, d + name, timeout=300)
    o = ctx.dir(d)
    ps(ctx, "volatile", "\n".join([
        "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,"
        "CommandLine,SessionId,HandleCount,WorkingSetSize,"
        "@{n='CreationDateUtc';e={if($_.CreationDate){$_.CreationDate.ToUniversalTime().ToString('o')}}},"
        "@{n='Owner';e={$o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner; if($o.User){\"$($o.Domain)\\$($o.User)\"}}} | "
        + export_csv(os.path.join(o, "processes.csv")),
        "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,"
        "@{n='ProcessName';e={(Get-Process -Id $_.OwningProcess).ProcessName}},"
        "@{n='CreationTimeUtc';e={if($_.CreationTime){$_.CreationTime.ToUniversalTime().ToString('o')}}} | "
        + export_csv(os.path.join(o, "tcp_connections.csv")),
        "Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess,"
        "@{n='ProcessName';e={(Get-Process -Id $_.OwningProcess).ProcessName}} | "
        + export_csv(os.path.join(o, "udp_endpoints.csv")),
        "Get-DnsClientCache | Select-Object Entry,Name,Type,Data,TimeToLive | "
        + export_csv(os.path.join(o, "dns_cache.csv")),
        "Get-SmbSession | Select-Object ClientComputerName,ClientUserName,NumOpens,SecondsExists | "
        + export_csv(os.path.join(o, "smb_sessions.csv")),
        "Get-SmbMapping | Select-Object LocalPath,RemotePath,Status | "
        + export_csv(os.path.join(o, "smb_mappings.csv")),
    ]))
    for name in ("processes.csv", "tcp_connections.csv", "udp_endpoints.csv", "dns_cache.csv",
                 "smb_sessions.csv", "smb_mappings.csv"):
        ctx.record_external(os.path.join(o, name), "powershell", "generated")


@module(OS, "process_images", "실행 중 프로세스·로드된 DLL의 서명 확인, 서명 없는 파일 수집", level="standard", order=20)
def process_images(ctx):
    o = ctx.dir("volatile")
    mods_csv = os.path.join(o, "process_modules.csv")
    sig_csv = os.path.join(o, "image_signatures.csv")
    ps(ctx, "process_images", "\n".join([
        "$paths = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)",
        "$rows = foreach ($p in Get-Process) { foreach ($m in $p.Modules) {",
        "  if ($m.FileName) { [void]$paths.Add($m.FileName) }",
        "  [pscustomobject]@{ProcessId=$p.Id; ProcessName=$p.ProcessName; Module=$m.ModuleName; Path=$m.FileName} } }",
        "$rows | " + export_csv(mods_csv),
        "Get-CimInstance Win32_Process | ForEach-Object { if ($_.ExecutablePath) { [void]$paths.Add($_.ExecutablePath) } }",
        "$paths | ForEach-Object {",
        "  $s = Get-AuthenticodeSignature -LiteralPath $_",
        "  $h = Get-FileHash -LiteralPath $_ -Algorithm SHA256",
        "  [pscustomobject]@{Path=$_; Status=[string]$s.Status; Signer=$s.SignerCertificate.Subject;"
        " IsOSBinary=$s.IsOSBinary; SHA256=$h.Hash} } | " + export_csv(sig_csv),
    ]), timeout=3600)
    for p in (mods_csv, sig_csv):
        ctx.record_external(p, "powershell", "generated")
    unsigned = [r for r in read_csv(sig_csv) if r.get("Status") not in ("Valid", None, "")]
    ctx.info("서명이 유효하지 않은 이미지 %d개", len(unsigned))
    for r in unsigned:
        ctx.copy(r["Path"], "unsigned", note="Authenticode=%s" % r.get("Status"))


@module(OS, "system", "시스템·계정·보안 설정(Defender, 방화벽, 감사 정책)", level="quick", order=30)
def system(ctx):
    d = "system/"
    for argv, name in [
        (["systeminfo"], "systeminfo.txt"),
        (["hostname"], "hostname.txt"),
        (["net", "user"], "net_user.txt"),
        (["net", "localgroup", "administrators"], "local_administrators.txt"),
        (["auditpol", "/get", "/category:*"], "auditpol.txt"),
        (["netsh", "advfirewall", "show", "allprofiles"], "firewall_profiles.txt"),
        (["w32tm", "/query", "/status"], "time_status.txt"),
    ]:
        ctx.run(argv, d + name, timeout=300)
    if ctx.at_least("standard"):
        ctx.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all", "verbose"],
                d + "firewall_rules.txt", timeout=600)
    o = ctx.dir(d)
    unin = ["HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
            "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
            "Registry::HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"]
    ps(ctx, "system", "\n".join([
        "Get-CimInstance Win32_OperatingSystem | Format-List * | Out-String -Width 4096 | "
        "Set-Content -Encoding UTF8 -Path " + _psq(os.path.join(o, "os.txt")),
        "Get-ItemProperty " + ",".join(_psq(x) for x in unin) + " | Where-Object { $_.DisplayName } | "
        "Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation,UninstallString,PSPath | "
        + export_csv(os.path.join(o, "installed_software.csv")),
        "Get-HotFix | Select-Object HotFixID,Description,InstalledOn,InstalledBy | "
        + export_csv(os.path.join(o, "hotfixes.csv")),
        "Get-LocalUser | Select-Object Name,Enabled,SID,LastLogon,PasswordLastSet,PasswordExpires,Description | "
        + export_csv(os.path.join(o, "local_users.csv")),
        "Get-LocalGroup | ForEach-Object { $g = $_; Get-LocalGroupMember -Group $g | "
        "Select-Object @{n='Group';e={$g.Name}},Name,ObjectClass,PrincipalSource } | "
        + export_csv(os.path.join(o, "local_group_members.csv")),
        # 공격자가 Defender 예외를 추가하는 경우가 많다
        "Get-MpComputerStatus | Format-List * | Out-String -Width 4096 | "
        "Set-Content -Encoding UTF8 -Path " + _psq(os.path.join(o, "defender_status.txt")),
        "Get-MpPreference | Format-List * | Out-String -Width 4096 | "
        "Set-Content -Encoding UTF8 -Path " + _psq(os.path.join(o, "defender_preferences.txt")),
        "Get-MpThreatDetection | Select-Object DetectionID,ThreatID,ProcessName,DomainUser,InitialDetectionTime,"
        "LastThreatStatusChangeTime,ActionSuccess,@{n='Resources';e={$_.Resources -join ' | '}} | "
        + export_csv(os.path.join(o, "defender_detections.csv")),
        "Get-PnpDevice | Where-Object { $_.InstanceId -like 'USB*' -or $_.InstanceId -like 'USBSTOR*' } | "
        "Select-Object Class,FriendlyName,InstanceId,Status,Present | "
        + export_csv(os.path.join(o, "usb_devices.csv")),
    ]))
    for fn in ("os.txt", "installed_software.csv", "hotfixes.csv", "local_users.csv",
               "local_group_members.csv", "defender_status.txt", "defender_preferences.txt",
               "defender_detections.csv", "usb_devices.csv"):
        ctx.record_external(os.path.join(o, fn), "powershell", "generated")
    ctx.copy_glob([_sys32("drivers", "etc", "*")], "system")


RUN_KEYS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
    r"Software\Microsoft\Command Processor",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    r"Software\Microsoft\Windows Defender\Exclusions\Paths",
    r"Software\Microsoft\Windows Defender\Exclusions\Processes",
    r"Software\Microsoft\Windows Defender\Exclusions\Extensions",
    r"System\CurrentControlSet\Control\Session Manager",
    r"System\CurrentControlSet\Control\Lsa",
    r"System\CurrentControlSet\Control\SecurityProviders\WDigest",
    r"System\CurrentControlSet\Control\Terminal Server",
    r"System\CurrentControlSet\Control\Print\Monitors",
]
RECURSE_KEYS = [
    r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    r"Software\Microsoft\Office\Excel\Addins",
    r"Software\Microsoft\Office\Word\Addins",
    r"Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}",
]


@module(OS, "persistence", "자동 실행(서비스, 예약 작업, Run 키, WMI 구독, 시작 프로그램)", level="quick", order=40)
def persistence(ctx):
    d = "persistence/"
    import platform
    arch = platform.machine().upper()
    auto = ctx.tool(*(["autorunsc64a.exe"] if arch == "ARM64" else ["autorunsc64.exe"] if arch.endswith("64")
                      else ["autorunsc.exe"]))
    if auto:   # -v(VirusTotal 조회)는 해시를 외부로 보내므로 쓰지 않는다
        ctx.run([auto, "-accepteula", "-nobanner", "-a", "*", "-c", "-h", "-s", "*"],
                d + "autoruns.csv", timeout=1800)
    ctx.run(["schtasks", "/query", "/fo", "csv", "/v"], d + "schtasks.csv", timeout=600)
    o = ctx.dir(d)
    keys = ",".join(_psq(k) for k in RUN_KEYS)
    rkeys = ",".join(_psq(k) for k in RECURSE_KEYS)
    ps(ctx, "persistence", "\n".join([
        "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName,"
        "ProcessId,Description | " + export_csv(os.path.join(o, "services.csv")),
        "Get-CimInstance Win32_SystemDriver | Select-Object Name,DisplayName,State,StartMode,PathName | "
        + export_csv(os.path.join(o, "drivers.csv")),
        "$wmi = foreach ($c in '__EventFilter','__EventConsumer','__FilterToConsumerBinding') {",
        "  \"===== $c\"; Get-CimInstance -Namespace root/subscription -ClassName $c | Format-List * | Out-String -Width 4096 }",
        "$wmi | Set-Content -Encoding UTF8 -Path " + _psq(os.path.join(o, "wmi_subscriptions.txt")),
        "$roots = @('Registry::HKEY_LOCAL_MACHINE') + (Get-ChildItem Registry::HKEY_USERS | "
        "Where-Object { $_.PSChildName -notmatch '_Classes$' } | ForEach-Object { 'Registry::HKEY_USERS\\' + $_.PSChildName })",
        "$out = foreach ($r in $roots) {",
        "  foreach ($k in @(%s)) { $p = \"$r\\$k\"; if (Test-Path -LiteralPath $p) {" % keys,
        "    \"===== $p\"; (Get-ItemProperty -LiteralPath $p | Format-List | Out-String -Width 4096).Trim(); '' } }",
        "  foreach ($k in @(%s)) { $p = \"$r\\$k\"; if (Test-Path -LiteralPath $p) {" % rkeys,
        "    Get-ChildItem -LiteralPath $p -Recurse | ForEach-Object {",
        "      \"===== $($_.Name)\"; (Get-ItemProperty -LiteralPath $_.PSPath | Format-List | Out-String -Width 4096).Trim(); '' } } } }",
        "$out | Set-Content -Encoding UTF8 -Path " + _psq(os.path.join(o, "registry_autostart.txt")),
    ]))
    for fn in ("services.csv", "drivers.csv", "wmi_subscriptions.txt", "registry_autostart.txt"):
        ctx.record_external(os.path.join(o, fn), "powershell", "generated")
    ctx.copy_tree(_sys32("Tasks"), "persistence/tasks")
    for gp in ("Machine", "User"):
        ctx.copy_tree(_sys32("GroupPolicy", gp, "Scripts"), "persistence/gpo_scripts")
    ctx.copy_tree(os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                               "Microsoft", "Windows", "Start Menu", "Programs", "StartUp"), "persistence/startup")
    for _, prof in profiles():
        ctx.copy_tree(os.path.join(prof, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu",
                                   "Programs", "Startup"), "persistence/startup")


QUICK_CHANNELS = [
    "Security", "System", "Application", "Windows PowerShell",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-Bits-Client/Operational",
    "Microsoft-Windows-WinRM/Operational",
    "Microsoft-Windows-SMBServer/Security",
    "Microsoft-Windows-CodeIntegrity/Operational",
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
]

# 주제별로 뽑아 볼 이벤트: (주제, 채널, 이벤트 ID)
EVENT_FILTERS = [
    ("logon", "Security", [4624, 4625, 4634, 4647, 4648, 4672, 4778, 4779]),
    ("account_change", "Security", [4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4738, 4740, 4756]),
    ("log_cleared", "Security", [1102]),
    ("log_cleared", "System", [104]),
    ("audit_policy_change", "Security", [4719, 4817, 4616]),
    ("service_install", "System", [7045, 7040, 7034]),
    ("service_install", "Security", [4697]),
    ("scheduled_task", "Security", [4698, 4699, 4700, 4701, 4702]),
    ("scheduled_task", "Microsoft-Windows-TaskScheduler/Operational", [106, 140, 141, 200, 201]),
    ("process_creation", "Security", [4688]),
    ("rdp", "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", [1149]),
    ("rdp", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", [21, 22, 23, 24, 25]),
    ("powershell", "Microsoft-Windows-PowerShell/Operational", [4103, 4104]),
    ("powershell", "Windows PowerShell", [400, 403, 600, 800]),
    ("defender", "Microsoft-Windows-Windows Defender/Operational", [1006, 1116, 1117, 1118, 1119, 5001, 5007, 5013]),
    ("wmi", "Microsoft-Windows-WMI-Activity/Operational", [5857, 5858, 5859, 5860, 5861]),
    ("bits", "Microsoft-Windows-Bits-Client/Operational", [3, 59, 60]),
    ("share_access", "Security", [5140, 5142, 5143, 5144]),
    ("power", "System", [41, 1074, 6005, 6006, 6008]),
    ("sysmon", "Microsoft-Windows-Sysmon/Operational", [1, 3, 7, 8, 10, 11, 12, 13, 22]),
]


def _channel_file(ch):
    return ch.replace("/", "%4") + ".evtx"


@module(OS, "eventlogs", "이벤트 로그 내보내기(.evtx)와 주요 이벤트 ID 텍스트 추출", level="quick", order=50, admin=True)
def eventlogs(ctx):
    wev = _sys32("wevtutil.exe")
    logdir = _sys32("winevt", "Logs")
    if ctx.at_least("standard"):
        chans = []
        for p in sorted(glob.glob(os.path.join(logdir, "*.evtx"))):
            try:
                if os.path.getsize(p) > 69632:      # 빈 evtx는 68KB
                    chans.append(os.path.basename(p)[:-5].replace("%4", "/"))
            except OSError:
                continue
        chans = sorted(set(chans) | set(QUICK_CHANNELS))
    else:
        chans = QUICK_CHANNELS
    for ch in chans:
        fname = _channel_file(ch)
        src = os.path.join(logdir, fname)
        dest = ctx.path("files/eventlogs/" + core.safe_component(fname))
        if ctx.dry_run:
            ctx.info("(dry-run) evtx %s", ch)
            continue
        rc = ctx.run([wev, "epl", ch, dest, "/ow:true"], "logs/wevtutil/%s.txt" % core.safe_component(ch))
        if rc != 0 and os.path.exists(src):
            rc = ctx.run([wev, "epl", src, dest, "/lf:true", "/ow:true"],
                         "logs/wevtutil/%s_lf.txt" % core.safe_component(ch))
        if rc == 0 and os.path.exists(dest):
            ctx.record_external(dest, src, "wevtutil-epl")
        elif os.path.exists(src):
            copy_locked(ctx, src, "eventlogs_raw")
    t = "TimeCreated[@SystemTime>='%s'" % ctx.log_since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    if ctx.until:
        t += " and @SystemTime<='%s'" % ctx.until.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    t += "]"
    for topic, ch, ids in EVENT_FILTERS:
        q = "*[System[(%s) and %s]]" % (" or ".join("EventID=%d" % i for i in ids), t)
        ctx.run([wev, "qe", ch, "/q:" + q, "/f:text", "/rd:true", "/c:50000"],
                "eventlogs_filtered/%s__%s.txt" % (topic, core.safe_component(ch.replace("/", "_"))))


@module(OS, "registry", "레지스트리 하이브(SAM/SECURITY/SYSTEM/SOFTWARE, 사용자 NTUSER·UsrClass)", level="quick", order=60, admin=True)
def registry(ctx):
    reg = _sys32("reg.exe")
    for hive in ("SAM", "SECURITY", "SYSTEM", "SOFTWARE"):
        dest = ctx.path("files/registry/HKLM/%s" % hive)
        if ctx.dry_run:
            continue
        if ctx.run([reg, "save", "HKLM\\" + hive, dest, "/y"], "logs/reg_save/%s.txt" % hive) == 0:
            ctx.record_external(dest, "HKLM\\" + hive, "reg-save")
        else:
            copy_locked(ctx, _sys32("config", hive), "registry/raw")
    loaded = set(h.upper() for h in loaded_user_hives())
    for sid, prof in profiles():
        tag = core.safe_component(sid or os.path.basename(prof))
        for hive_name, fname, rel in (("", "NTUSER.DAT", "NTUSER.DAT"),
                                      ("_Classes", "UsrClass.dat",
                                       os.path.join("AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"))):
            key = (sid or "") + hive_name
            dest = ctx.path("files/registry/users/%s/%s" % (tag, fname))
            if sid and key.upper() in loaded and not ctx.dry_run:
                if ctx.run([reg, "save", "HKU\\" + key, dest, "/y"], "logs/reg_save/%s.txt" % core.safe_component(key)) == 0:
                    ctx.record_external(dest, "HKU\\" + key, "reg-save", note=prof)
                    continue
            src = os.path.join(prof, rel)
            if os.path.exists(src):
                copy_locked(ctx, src, "registry/user_files")
                for suffix in (".LOG1", ".LOG2"):
                    if os.path.exists(src + suffix):
                        copy_locked(ctx, src + suffix, "registry/user_files")
    if ctx.at_least("standard"):
        ctx.copy_tree(_sys32("config", "RegBack"), "registry/regback", max_size=0)


@module(OS, "execution", "실행 흔적(Prefetch, Amcache, ShimCache, SRUM, PCA)", level="quick", order=70, admin=True)
def execution(ctx):
    root = _sysroot()
    ctx.copy_glob([os.path.join(root, "Prefetch", "*")], "execution/prefetch", max_size=0)
    for f in ("Amcache.hve", "Amcache.hve.LOG1", "Amcache.hve.LOG2"):
        p = os.path.join(root, "AppCompat", "Programs", f)
        if os.path.exists(p):
            copy_locked(ctx, p, "execution/amcache")
    ctx.copy_glob([os.path.join(root, "AppCompat", "Programs", "RecentFileCache.bcf")], "execution/amcache")
    ctx.copy_tree(os.path.join(root, "appcompat", "pca"), "execution/pca")
    shim = ctx.tool("ShimCacheParser.exe")
    if shim:
        out = ctx.path("execution/shimcache.csv")
        ctx.run([shim, "-l", "-o", out], "logs/shimcacheparser.txt")
        if os.path.exists(out):
            ctx.record_external(out, "SYSTEM hive (live)", "ShimCacheParser")
    if ctx.at_least("standard"):
        for f in ("SRUDB.dat", "SRU.chk", "SRU.log"):
            p = _sys32("sru", f)
            if os.path.exists(p):
                copy_locked(ctx, p, "execution/srum")
        epl = ctx.tool("ExecutedProgramsList.exe")
        if epl:
            ctx.run([epl, "/scomma", ctx.path("execution/executed_programs_list.csv")],
                    "logs/executed_programs_list.txt")


@module(OS, "user_activity", "사용자 흔적(PowerShell 기록, 최근 파일·점프 목록, 휴지통, 아이콘·썸네일 캐시)", level="quick", order=80)
def user_activity(ctx):
    for sid, prof in profiles():
        roam = os.path.join(prof, "AppData", "Roaming")
        local = os.path.join(prof, "AppData", "Local")
        ctx.copy_glob([os.path.join(roam, "Microsoft", "Windows", "PowerShell", "PSReadLine", "*.txt")],
                      "user/powershell_history", max_size=0)
        ctx.copy_tree(os.path.join(roam, "Microsoft", "Windows", "Recent"), "user/recent")
        ctx.copy_glob([os.path.join(prof, "Documents", "Default.rdp")], "user/rdp")
        if ctx.at_least("standard"):
            ctx.copy_glob([os.path.join(local, "Microsoft", "Windows", "Explorer", "iconcache_*.db"),
                           os.path.join(local, "IconCache.db")], "user/iconcache", max_size=0)
            ctx.copy_glob([os.path.join(local, "ConnectedDevicesPlatform", "*", "ActivitiesCache.db*")],
                          "user/timeline", max_size=0)
            webcache = os.path.join(local, "Microsoft", "Windows", "WebCache", "WebCacheV01.dat")
            if os.path.exists(webcache):
                copy_locked(ctx, webcache, "user/webcache")
        if ctx.at_least("full"):
            ctx.copy_glob([os.path.join(local, "Microsoft", "Windows", "Explorer", "thumbcache_*.db")],
                          "user/thumbcache", max_size=0)
            ctx.copy_tree(os.path.join(local, "Microsoft", "Terminal Server Client", "Cache"), "user/rdp_cache")
    # 휴지통: $I(삭제 정보)는 모두 복사, $R(내용)은 목록·해시만
    for drv in fixed_drives():
        rb = os.path.join(drv, "$Recycle.Bin")
        ctx.copy_tree(rb, "user/recycle_bin", match=lambda p: os.path.basename(p).startswith("$I"))
        ctx.file_listing("user/recycle_bin_%s.csv" % drv[0], [rb], hash_files=True)


CHROMIUM = [("Google", "Chrome"), ("Microsoft", "Edge"), ("BraveSoftware", "Brave-Browser"),
            ("Naver", "Naver Whale"), ("Chromium",)]
CHROMIUM_FILES = ("History", "History-journal", "Bookmarks", "Preferences", "Secure Preferences",
                  "Shortcuts", "Top Sites")


@module(OS, "browsers", "브라우저 방문·다운로드 기록과 확장 프로그램(쿠키·저장 비밀번호는 제외)", level="standard", order=90)
def browsers(ctx):
    for _, prof in profiles():
        local = os.path.join(prof, "AppData", "Local")
        roam = os.path.join(prof, "AppData", "Roaming")
        for parts in CHROMIUM:
            for hist in glob.glob(os.path.join(local, *(parts + ("User Data", "*", "History")))):
                pdir = os.path.dirname(hist)
                for f in CHROMIUM_FILES:
                    p = os.path.join(pdir, f)
                    if os.path.exists(p):
                        copy_locked(ctx, p, "browsers")
                ctx.copy_glob([os.path.join(pdir, "Extensions", "*", "*", "manifest.json")], "browsers")
        bases = [os.path.join(roam, "Opera Software", "Opera Stable")]
        for b in bases:
            if os.path.exists(os.path.join(b, "History")):
                for f in CHROMIUM_FILES:
                    if os.path.exists(os.path.join(b, f)):
                        copy_locked(ctx, os.path.join(b, f), "browsers")
        for fp in glob.glob(os.path.join(roam, "Mozilla", "Firefox", "Profiles", "*")):
            for f in ("places.sqlite", "places.sqlite-wal", "extensions.json", "addons.json", "prefs.js",
                      "handlers.json"):
                p = os.path.join(fp, f)
                if os.path.exists(p):
                    copy_locked(ctx, p, "browsers")
    bhv = ctx.tool("BrowsingHistoryView64.exe", "BrowsingHistoryView.exe")
    if bhv:
        ctx.run([bhv, "/HistorySource", "1", "/VisitTimeFilterType", "1", "/LoadIE", "1", "/LoadFirefox", "1",
                 "/LoadChrome", "1", "/LoadSafari", "0", "/sort", "~2",
                 "/scomma", ctx.path("browsers/browsing_history.csv")], "logs/browsinghistoryview.txt")
    if ctx.at_least("full"):
        for exe, name in (("ChromeCacheView.exe", "chrome"), ("IECacheView.exe", "ie"),
                          ("MozillaCacheView.exe", "mozilla")):
            t = ctx.tool(exe)
            if t:
                ctx.run([t, "/scomma", ctx.path("browsers/cache_%s.csv" % name)], "logs/%s.txt" % exe)


@module(OS, "app_logs", "Defender·USB 설치·IIS·방화벽 로그", level="standard", order=95)
def app_logs(ctx):
    pd = os.environ.get("ProgramData", r"C:\ProgramData")
    ctx.copy_glob([os.path.join(pd, "Microsoft", "Windows Defender", "Support", "*")], "logs/defender")
    ctx.copy_glob([os.path.join(_sysroot(), "INF", "setupapi.dev*.log")], "logs/setupapi", max_size=0)
    ctx.copy_glob([_sys32("LogFiles", "Firewall", "*.log")], "logs/firewall")
    if os.path.isdir(os.path.join(_sysdrive() + "\\", "inetpub", "logs")):
        ctx.copy_tree(os.path.join(_sysdrive() + "\\", "inetpub", "logs"), "logs/iis")
    ctx.file_listing("logs/defender_quarantine.csv",
                     [os.path.join(pd, "Microsoft", "Windows Defender", "Quarantine")])
    ctx.file_listing("logs/wer_reports.csv",
                     [os.path.join(pd, "Microsoft", "Windows", "WER")], max_depth=3)


@module(OS, "ntfs", "NTFS 메타데이터($MFT, UsnJrnl, full이면 $LogFile·$J 원본)", level="standard", order=100, admin=True)
def ntfs(ctx):
    icat = ctx.tool("icat.exe")
    fls = ctx.tool("fls.exe")
    fsutil = _sys32("fsutil.exe")
    for drv in ntfs_drives():
        vol = "\\\\.\\%s:" % drv
        base = "files/ntfs/%s" % drv
        got_mft = False
        if icat and not ctx.dry_run:
            dest = ctx.path(base + "/$MFT")
            if ctx.run([icat, vol, "0"], base + "/$MFT", timeout=7200) == 0 and os.path.getsize(dest) > 0:
                ctx.record_external(dest, "%s:\\$MFT" % drv, "icat")
                got_mft = True
            else:       # 실패한 icat 이 남긴 빈 출력은 증거로 남기지 않는다
                for p in (dest, dest + ".stderr"):
                    if os.path.exists(p) and os.path.getsize(p) == 0:
                        os.remove(p)
                ctx.hashed.pop(base + "/$MFT", None)
        if not got_mft and not ctx.dry_run:
            fc = ctx.tool("forecopy.exe", "forecopy_handy.exe")
            if fc and drv + ":" == _sysdrive().upper():
                d = ctx.dir(base + "/forecopy")
                ctx.run([fc, "-m", d], "logs/forecopy_mft_%s.txt" % drv, timeout=7200)
                for root, _, files in os.walk(d):
                    for fn in files:
                        p = os.path.join(root, fn)
                        if os.path.getsize(p) > 0:
                            ctx.record_external(p, "%s:\\$MFT" % drv, "forecopy-m")
                            got_mft = True
        if not got_mft:
            ctx.error("%s: $MFT 수집 실패 — icat·forecopy 가 없거나 둘 다 실패(logs/ 확인, 관리자 권한 필요)" % drv)
        # UsnJrnl: fsutil 파싱본(내장, 기본) + full이면 원본 $J
        ctx.run([fsutil, "usn", "readjournal", drv + ":", "csv"], "ntfs/%s_usnjrnl.csv" % drv, timeout=7200)
        if ctx.at_least("full") and icat and fls and not ctx.dry_run:
            dest = ctx.path(base + "/$LogFile")
            if ctx.run([icat, vol, "2"], base + "/$LogFile", timeout=7200) == 0:
                ctx.record_external(dest, "%s:\\$LogFile" % drv, "icat")
            listing = ctx.capture([fls, vol, "11"], timeout=600) or b""
            m = re.search(r"(\d+-\d+-\d+):\s+\$UsnJrnl:\$J", listing.decode("utf-8", "replace"))
            if m:
                dest = ctx.path(base + "/$UsnJrnl_$J")
                if ctx.run([icat, "-h", vol, m.group(1)], base + "/$UsnJrnl_$J", timeout=7200) == 0:
                    ctx.record_external(dest, "%s:\\$Extend\\$UsnJrnl:$J" % drv, "icat -h")
            else:
                ctx.error("%s: $UsnJrnl:$J 를 찾지 못함" % drv)


@module(OS, "hashes", "임시·시작·공용 폴더 해시 목록(standard부터 실행 파일 수집)", level="quick", order=110)
def hashes(ctx):
    pd = os.environ.get("ProgramData", r"C:\ProgramData")
    temp_like = [os.path.join(_sysroot(), "Temp"), os.path.join(_sysdrive() + "\\", "Users", "Public"),
                 os.path.join(_sysdrive() + "\\", "PerfLogs"), os.path.join(_sysdrive() + "\\", "Temp")]
    listed_only = [os.path.join(pd, "Microsoft", "Windows", "Start Menu")]
    for _, prof in profiles():
        temp_like.append(os.path.join(prof, "AppData", "Local", "Temp"))
        listed_only += [os.path.join(prof, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu"),
                        os.path.join(prof, "Downloads")]
    collect = _collect_exec("suspicious/temp_like") if ctx.at_least("standard") else None
    n = ctx.file_listing("hashes/temp_public.csv", temp_like, hash_files=True, collect=collect)
    # Downloads 는 정상 설치 파일이 많아 목록·해시만 남긴다(시작 프로그램은 persistence 가 복사)
    n += ctx.file_listing("hashes/startmenu_downloads.csv", listed_only, hash_files=True)
    ctx.info("해시 목록 %d행", n)
    # ProgramData 최상위 두 단계: 악성코드가 자주 숨는 곳
    ctx.file_listing("hashes/programdata_depth2.csv", [pd], hash_files=True, max_depth=1, collect=collect)


@module(OS, "sweep", "전체 드라이브 탐색: 웹셸·스크립트 수집, System32 해시, 기간 내 변경 파일", level="full", order=120)
def sweep(ctx):
    drives = fixed_drives()
    ctx.file_listing("sweep/scripts_webshells.csv", drives, hash_files=True,
                     exclude_names=SWEEP_EXCLUDE,
                     only=lambda p, st: bool(SCRIPT_EXT.search(p)),
                     collect=lambda p, st, kind: "sweep/scripts")
    ctx.file_listing("sweep/system32_hashes.csv", [_sys32()], hash_files=True, hash_max=50 << 20)
    if ctx.since is not None:
        ctx.info("기간 내 변경 파일 탐색(실행 파일·스크립트는 수집)")
        for drv in drives:
            ctx.file_listing("sweep/timeline_%s.csv" % drv[0], [drv],
                             only=lambda p, st: ctx.in_window(st),
                             collect=lambda p, st, kind: "period" if (kind in ("pe", "script") or EXEC_EXT.search(p))
                             and ctx.in_window(st, ctime=False) else None)
