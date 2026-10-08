# -*- coding: utf-8 -*-
"""macOS 수집 모듈.

TCC 보호 영역(Safari, TCC.db, KnowledgeC, 메일 등)은 실행하는 터미널에
'전체 디스크 접근 권한'이 있어야 읽힌다. 없으면 system 모듈이 경고를 남긴다.
Apple Silicon에서 쓸 만한 메모리 수집 도구가 없어 memory 모듈은 두지 않았다.
"""
import glob
import os
import plistlib
import re

from . import core
from .core import module

OS = "macos"

SHELL_FILES = (".zsh_history", ".bash_history", ".sh_history", ".python_history", ".lesshst",
               ".viminfo", ".mysql_history", ".psql_history", ".node_repl_history", ".wget-hsts")
RC_FILES = (".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout", ".bash_profile", ".bashrc",
            ".profile", ".ssh/authorized_keys", ".ssh/authorized_keys2", ".ssh/config", ".ssh/known_hosts")


def users(ctx):
    """(사용자 이름, 홈 경로) — UID 500 이상 사용자와 root."""
    res = []
    out = ctx.capture(["dscl", ".", "-list", "/Users", "UniqueID"]) or b""
    for line in out.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("-").isdigit():
            name, uid = parts[0], int(parts[1])
            if uid >= 500 or uid == 0:
                home = os.path.expanduser("~" + name)
                if home.startswith("~"):
                    home = "/Users/" + name
                if os.path.isdir(home):
                    res.append((name, home))
    if not res:
        res = [(os.path.basename(p), p) for p in glob.glob("/Users/*")
               if os.path.isdir(p) and not os.path.basename(p).startswith(".")]
        if os.path.isdir("/var/root"):
            res.append(("root", "/var/root"))
    return res


def codesign_info(ctx, path):
    """codesign -dv 결과에서 서명 상태를 뽑는다."""
    out = ctx.capture(["codesign", "-dv", "--verbose=2", path], merge_stderr=True, timeout=30, record=False)
    text = (out or b"").decode("utf-8", "replace")
    info = {"signed": "yes", "authority": "", "team_id": "", "identifier": "", "flags": ""}
    if "not signed at all" in text:
        info["signed"] = "no"
    elif "Signature=adhoc" in text:
        info["signed"] = "adhoc"
    elif not text.strip():
        info["signed"] = "unknown"
    m = re.search(r"^Authority=(.+)$", text, re.M)
    if m:
        info["authority"] = m.group(1)
    for key, field in (("TeamIdentifier", "team_id"), ("Identifier", "identifier")):
        m = re.search(r"^%s=(.+)$" % key, text, re.M)
        if m:
            info[field] = m.group(1)
    m = re.search(r"flags=(\S+)", text)
    if m:
        info["flags"] = m.group(1)
    return info


def _cmds(ctx, d, cmds, timeout=600):
    for argv, name in cmds:
        ctx.run(argv, d + name, timeout=timeout)


# ---------------------------------------------------------------- 모듈

@module(OS, "volatile", "프로세스·네트워크·세션 등 휘발성 정보", level="quick", order=10)
def volatile(ctx):
    _cmds(ctx, "volatile/", [
        (["ps", "-axwwo", "user,pid,ppid,lstart,etime,state,command"], "ps.txt"),
        (["lsof", "-nP", "-i"], "lsof_network.txt"),
        (["netstat", "-anv"], "netstat.txt"),
        (["ifconfig", "-a"], "ifconfig.txt"),
        (["arp", "-an"], "arp.txt"),
        (["netstat", "-rn"], "routes.txt"),
        (["scutil", "--dns"], "dns.txt"),
        (["scutil", "--proxy"], "proxy.txt"),
        (["who", "-a"], "who.txt"),
        (["w"], "w.txt"),
        (["launchctl", "list"], "launchctl_list.txt"),
        (["kmutil", "showloaded"], "kexts_loaded.txt"),
        (["systemextensionsctl", "list"], "system_extensions.txt"),
    ])
    if ctx.at_least("standard"):
        ctx.run(["lsof", "-nP"], "volatile/lsof_all.txt", timeout=900)


@module(OS, "process_images", "실행 중 프로세스 실행 파일의 해시·코드 서명, 미서명·adhoc 수집", level="standard", order=20)
def process_images(ctx):
    out = ctx.capture(["ps", "-axo", "pid=,comm="]) or b""
    by_path = {}
    for line in out.decode("utf-8", "replace").splitlines():
        line = line.strip()
        pid, _, path = line.partition(" ")
        path = path.strip()
        if path.startswith("/") and os.path.isfile(path):
            by_path.setdefault(path, []).append(pid)
    fh, w = ctx.csv_writer("volatile/process_images.csv",
                           ["path", "pids", "sha256", "signed", "authority", "team_id", "identifier", "flags"])
    try:
        for path in sorted(by_path):
            try:
                sha = core.hash_file(path)[0]
            except OSError:
                sha = ""
            info = codesign_info(ctx, path)
            w.writerow([path, " ".join(by_path[path]), sha, info["signed"], info["authority"],
                        info["team_id"], info["identifier"], info["flags"]])
            if info["signed"] in ("no", "adhoc"):
                ctx.copy(path, "unsigned", note="codesign=%s" % info["signed"])
    finally:
        fh.close()


@module(OS, "system", "시스템 정보·계정·보안 설정(SIP, Gatekeeper, FileVault, 프로파일)", level="quick", order=30)
def system(ctx):
    try:
        with open("/Library/Application Support/com.apple.TCC/TCC.db", "rb"):
            pass
    except PermissionError:
        ctx.warn("전체 디스크 접근 권한이 없습니다. Safari·TCC·KnowledgeC 등은 수집되지 않습니다 "
                 "(시스템 설정 > 개인정보 보호 및 보안 > 전체 디스크 접근 권한에 터미널 추가)")
        ctx.error("Full Disk Access 없음")
    except OSError:
        pass
    _cmds(ctx, "system/", [
        (["sw_vers"], "sw_vers.txt"),
        (["uname", "-a"], "uname.txt"),
        (["hostname"], "hostname.txt"),
        (["uptime"], "uptime.txt"),
        (["system_profiler", "SPSoftwareDataType", "SPHardwareDataType"], "system_profiler.txt"),
        (["csrutil", "status"], "sip.txt"),
        (["spctl", "--status"], "gatekeeper.txt"),
        (["fdesetup", "status"], "filevault.txt"),
        (["nvram", "-p"], "nvram.txt"),
        (["profiles", "list", "-all"], "profiles.txt"),
        (["dscl", ".", "-list", "/Users", "UniqueID"], "users.txt"),
        (["dscl", ".", "-read", "/Groups/admin", "GroupMembership"], "admin_group.txt"),
        (["last"], "last.txt"),
        (["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], "firewall.txt"),
        (["systemsetup", "-getremotelogin"], "remote_login.txt"),
        (["sharing", "-l"], "sharing.txt"),
        (["softwareupdate", "--history"], "softwareupdate_history.txt"),
    ])
    if ctx.at_least("standard"):
        ctx.run(["system_profiler", "-detailLevel", "mini", "SPApplicationsDataType"],
                "system/applications.txt", timeout=900)
    for p in ("/Library/Receipts/InstallHistory.plist", "/etc/hosts", "/etc/sudoers",
              "/etc/ssh/sshd_config", "/etc/resolv.conf", "/etc/zshrc", "/etc/zprofile",
              "/etc/profile", "/etc/bashrc", "/etc/crontab"):
        if os.path.exists(p):
            ctx.copy(os.path.realpath(p), "system")
    ctx.copy_tree("/private/etc/sudoers.d", "system")
    ctx.copy_tree("/private/etc/pam.d", "system")
    ctx.copy_tree("/private/etc/ssh/sshd_config.d", "system")


LAUNCH_DIRS = ["/Library/LaunchAgents", "/Library/LaunchDaemons"]


def _launch_summary(ctx, plist_paths):
    fh, w = ctx.csv_writer("persistence/launch_items.csv",
                           ["plist", "label", "program", "arguments", "run_at_load", "keep_alive",
                            "disabled", "program_sha256", "signed", "authority", "team_id", "plist_mtime"])
    try:
        for p in plist_paths:
            try:
                with open(p, "rb") as f:
                    d = plistlib.load(f)
            except Exception as e:
                ctx.error("plist 해석 실패: %s" % p, e)
                continue
            if not isinstance(d, dict):
                continue
            args = d.get("ProgramArguments") or []
            prog = d.get("Program") or (args[0] if args else "")
            sha, info = "", {"signed": "", "authority": "", "team_id": ""}
            if prog and os.path.isfile(prog):
                try:
                    sha = core.hash_file(prog)[0]
                except OSError:
                    pass
                info = codesign_info(ctx, prog)
                if info["signed"] in ("no", "adhoc"):
                    ctx.copy(prog, "persistence/programs", note="launch item %s" % p)
            try:
                mt = core.ts_iso(os.stat(p).st_mtime)
            except OSError:
                mt = ""
            w.writerow([p, d.get("Label", ""), prog, " ".join(str(a) for a in args),
                        d.get("RunAtLoad", ""), d.get("KeepAlive", ""), d.get("Disabled", ""),
                        sha, info["signed"], info["authority"], info["team_id"], mt])
    finally:
        fh.close()


@module(OS, "persistence", "자동 실행(LaunchAgents/Daemons, 로그인 항목, cron, 셸 설정, SSH 키)", level="quick", order=40)
def persistence(ctx):
    plists = []
    dirs = list(LAUNCH_DIRS)
    for _, home in users(ctx):
        dirs.append(os.path.join(home, "Library", "LaunchAgents"))
        for f in RC_FILES:
            p = os.path.join(home, f)
            if os.path.isfile(p):
                ctx.copy(p, "persistence/user_rc")
        ctx.copy_glob([os.path.join(home, "Library", "Application Support",
                                    "com.apple.backgroundtaskmanagementagent", "*")], "persistence/btm")
        ctx.copy_glob([os.path.join(home, "Library", "Preferences", "com.apple.loginitems.plist")],
                      "persistence/login_items")
    for d in dirs:
        ctx.copy_tree(d, "persistence/launch")
        plists += sorted(glob.glob(os.path.join(d, "*.plist")))
    _launch_summary(ctx, plists)
    # /System 쪽은 봉인 볼륨이라 바뀔 일이 드물지만 목록·해시는 남긴다
    ctx.file_listing("persistence/system_launch_items.csv",
                     ["/System/Library/LaunchAgents", "/System/Library/LaunchDaemons"], hash_files=True)
    for d in ("/Library/StartupItems", "/private/etc/periodic", "/private/etc/emond.d",
              "/usr/lib/cron/tabs", "/usr/lib/cron/jobs", "/private/var/at/tabs",
              "/Library/Security/SecurityAgentPlugins", "/Library/DirectoryServices/PlugIns"):
        ctx.copy_tree(d, "persistence/other", max_depth=3)
    ctx.copy_glob(["/Library/Preferences/com.apple.loginwindow.plist",
                   "/private/var/db/com.apple.xpc.launchd/disabled.*.plist"], "persistence/other")
    ctx.file_listing("persistence/extensions.csv",
                     ["/Library/Extensions", "/Library/SystemExtensions", "/Library/Security",
                      "/Library/PrivilegedHelperTools"], hash_files=True, max_depth=3,
                     collect=lambda p, st, kind: "persistence/helpers" if kind in ("macho", "script")
                     and p.startswith("/Library/PrivilegedHelperTools") else None)
    if ctx.is_admin:    # root가 아니면 인증 창을 띄우고 기다리므로 실행하지 않는다
        ctx.run(["sfltool", "dumpbtm"], "persistence/btm_dump.txt", timeout=120)


LOG_PREDICATES = [
    ("auth", 'process IN {"sudo","su","sshd","sshd-session","login","screensharingd","authd"}'),
    ("gatekeeper_xprotect", 'subsystem IN {"com.apple.syspolicy","com.apple.syspolicy.exec",'
                            '"com.apple.XProtectFramework"} OR process IN {"XProtect","XprotectService"}'),
    ("install", 'process IN {"installd","installer","package_script_service","system_installd"}'),
    ("background_tasks", 'subsystem == "com.apple.backgroundtaskmanagement"'),
    ("remote_access", 'process IN {"screensharingd","ARDAgent","sshd","sshd-session"}'),
]


@module(OS, "logs", "통합 로그 주요 항목(ndjson), /var/log, 감사 로그", level="quick", order=50)
def logs(ctx):
    start = ctx.log_since.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    base = ["log", "show", "--style", "ndjson", "--info", "--start", start]
    if ctx.until:
        base += ["--end", ctx.until.astimezone().strftime("%Y-%m-%d %H:%M:%S")]
    for name, pred in LOG_PREDICATES:
        ctx.run(base + ["--predicate", pred], "unified_log/%s.ndjson" % name, timeout=3600)
    if ctx.at_least("standard"):
        ctx.run(base + ["--predicate", 'subsystem == "com.apple.TCC"'], "unified_log/tcc.ndjson", timeout=3600)
    ctx.copy_tree("/private/var/log", "logs/var_log", max_depth=3)
    ctx.file_listing("logs/diagnostic_reports.csv",
                     ["/Library/Logs/DiagnosticReports", "/private/var/log/DiagnosticMessages"], max_depth=2)
    if ctx.at_least("standard"):
        ctx.copy_tree("/private/var/audit", "logs/audit")
    if ctx.at_least("full") and not ctx.dry_run:
        dest = ctx.path("files/unified_log/system.logarchive")
        argv = ["log", "collect", "--output", dest, "--start", start]
        if ctx.run(argv, "logs/log_collect.txt", timeout=4 * 3600) == 0:
            for root, _, files in os.walk(dest):
                for fn in files:
                    ctx.record_external(os.path.join(root, fn), "unified log", "log collect")


@module(OS, "user_activity", "사용자 흔적(셸 기록, 다운로드 격리 기록, 최근 항목, TCC, KnowledgeC)", level="quick", order=80)
def user_activity(ctx):
    ctx.copy_glob(["/Library/Application Support/com.apple.TCC/TCC.db"], "user/tcc", max_size=0)
    for name, home in users(ctx):
        for f in SHELL_FILES:
            p = os.path.join(home, f)
            if os.path.isfile(p):
                ctx.copy(p, "user/shell_history", max_size=0)
        ctx.copy_tree(os.path.join(home, ".zsh_sessions"), "user/shell_history")
        lib = os.path.join(home, "Library")
        ctx.copy_glob([os.path.join(lib, "Preferences", "com.apple.LaunchServices.QuarantineEventsV2*")],
                      "user/quarantine_events", max_size=0)
        ctx.copy_tree(os.path.join(lib, "Application Support", "com.apple.sharedfilelist"), "user/recent_items")
        ctx.copy_glob([os.path.join(lib, "Application Support", "com.apple.TCC", "TCC.db")], "user/tcc", max_size=0)
        if ctx.at_least("standard"):
            ctx.copy_glob([os.path.join(lib, "Application Support", "Knowledge", "knowledgeC.db*")],
                          "user/knowledgec", max_size=0)
            dl = os.path.join(home, "Downloads")
            if os.path.isdir(dl):
                ctx.run(["xattr", "-lr", dl], "user/downloads_xattr_%s.txt" % core.safe_component(name), timeout=600)
                ctx.file_listing("user/downloads_%s.csv" % core.safe_component(name), [dl],
                                 hash_files=True, max_depth=2)


CHROMIUM = ["Google/Chrome", "Microsoft Edge", "BraveSoftware/Brave-Browser", "Naver/Whale", "Chromium",
            "com.operasoftware.Opera"]
CHROMIUM_FILES = ("History", "History-journal", "Bookmarks", "Preferences", "Secure Preferences",
                  "Shortcuts", "Top Sites")


@module(OS, "browsers", "브라우저 방문·다운로드 기록과 확장 프로그램(쿠키·저장 비밀번호는 제외)", level="standard", order=90)
def browsers(ctx):
    for _, home in users(ctx):
        lib = os.path.join(home, "Library")
        ctx.copy_glob([os.path.join(lib, "Safari", f) for f in
                       ("History.db", "History.db-wal", "Downloads.plist", "Bookmarks.plist", "Extensions/*.plist")],
                      "browsers", max_size=0)
        for b in CHROMIUM:
            base = os.path.join(lib, "Application Support", *b.split("/"))
            for hist in glob.glob(os.path.join(base, "*", "History")):
                pdir = os.path.dirname(hist)
                ctx.copy_glob([os.path.join(pdir, f) for f in CHROMIUM_FILES], "browsers", max_size=0)
                ctx.copy_glob([os.path.join(pdir, "Extensions", "*", "*", "manifest.json")], "browsers")
        for fp in glob.glob(os.path.join(lib, "Application Support", "Firefox", "Profiles", "*")):
            ctx.copy_glob([os.path.join(fp, f) for f in ("places.sqlite", "places.sqlite-wal", "extensions.json",
                                                          "addons.json", "prefs.js", "handlers.json")],
                          "browsers", max_size=0)


@module(OS, "fsevents", "FSEvents(/.fseventsd) 원본", level="full", order=100, admin=True)
def fsevents(ctx):
    ctx.copy_tree("/System/Volumes/Data/.fseventsd" if os.path.isdir("/System/Volumes/Data/.fseventsd")
                  else "/.fseventsd", "fsevents")


TMP_ROOTS = ["/private/tmp", "/private/var/tmp", "/Users/Shared"]


@module(OS, "hashes", "임시·공유 폴더 해시 목록(standard부터 Mach-O·스크립트 수집)", level="quick", order=110)
def hashes(ctx):
    collect = None
    if ctx.at_least("standard"):
        collect = lambda p, st, kind: "suspicious/temp_like" if kind in ("macho", "script") else None  # noqa: E731
    roots = list(TMP_ROOTS)
    for _, home in users(ctx):
        roots.append(os.path.join(home, "Library", "Application Support"))
    ctx.file_listing("hashes/temp_shared.csv", TMP_ROOTS, hash_files=True, collect=collect)
    # Application Support 최상위: 정상 앱과 섞여 있으므로 목록·해시만
    ctx.file_listing("hashes/app_support_depth1.csv", roots[len(TMP_ROOTS):] + ["/Library/Application Support"],
                     hash_files=True, max_depth=1)


@module(OS, "sweep", "기간 내 변경 파일 타임라인(--since 필요), /Applications 실행 파일 서명", level="full", order=120)
def sweep(ctx):
    fh, w = ctx.csv_writer("sweep/applications.csv", ["app", "executable", "sha256", "signed", "authority", "team_id"])
    try:
        for app in sorted(glob.glob("/Applications/*.app") + glob.glob("/Applications/*/*.app")):
            info_plist = os.path.join(app, "Contents", "Info.plist")
            try:
                with open(info_plist, "rb") as f:
                    exe = plistlib.load(f).get("CFBundleExecutable")
            except Exception:
                continue
            path = os.path.join(app, "Contents", "MacOS", exe or "")
            if not exe or not os.path.isfile(path):
                continue
            try:
                sha = core.hash_file(path)[0]
            except OSError:
                sha = ""
            info = codesign_info(ctx, path)
            w.writerow([app, path, sha, info["signed"], info["authority"], info["team_id"]])
    finally:
        fh.close()
    if ctx.since is None:
        ctx.info("--since 가 없어 기간 타임라인은 건너뜀")
        return
    roots = ["/Users", "/Library", "/private/etc", "/private/var", "/Applications", "/usr/local", "/opt"]
    ctx.file_listing("sweep/timeline.csv", roots,
                     exclude=["/private/var/db/uuidtext", "/private/var/db/diagnostics", "/private/var/vm",
                              "/private/var/folders"],
                     only=lambda p, st: ctx.in_window(st),
                     collect=lambda p, st, kind: "period" if kind in ("macho", "script")
                     and ctx.in_window(st, ctime=False) else None)
