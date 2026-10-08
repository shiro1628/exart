# -*- coding: utf-8 -*-
"""Linux 수집 모듈.

컨테이너 안에서도 돌도록 ps·ss·lsof 같은 명령에 기대지 않고 /proc 를 직접 읽는다.
실행 파일이 지워진 채 돌고 있는 프로세스(채굴기에 흔함)는 /proc/<pid>/exe 로 원본을 건진다.

--fs-root 를 주면 파일은 그 아래에서 읽는다. 셸·파이썬이 없는 대상 컨테이너는
`kubectl debug -it <pod> --image=python:3.12-slim --target=<컨테이너>` 로 붙은 뒤
대상 프로세스 PID의 /proc/<PID>/root 를 --fs-root 로 주면 된다(PID·네트워크 네임스페이스 공유).
이때 패키지·systemd·journal 같은 명령 결과는 디버그 컨테이너 것이므로 건너뛴다.
"""
import os
import shutil
import socket
import stat
import struct

from . import core
from .core import module

OS = "linux"

HISTORY_FILES = (".bash_history", ".zsh_history", ".ash_history", ".sh_history", ".python_history",
                 ".mysql_history", ".psql_history", ".rediscli_history", ".node_repl_history",
                 ".viminfo", ".lesshst", ".wget-hsts")
RC_FILES = (".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile",
            ".zshenv", ".zlogin", ".ssh/authorized_keys", ".ssh/authorized_keys2", ".ssh/config",
            ".ssh/known_hosts", ".ssh/rc")
TMP_DIRS = ["/tmp", "/var/tmp", "/dev/shm", "/run/shm"]
NO_HOME = {"/", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/dev/null", "/nonexistent", "/var/empty",
           "/proc", "/sys"}
TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
              "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
              "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV"}


def R(ctx, path):
    """대상 파일시스템 경로(--fs-root 반영)."""
    if ctx.fs_root in ("/", ""):
        return path
    return os.path.join(ctx.fs_root, path.lstrip("/"))


def native(ctx):
    """명령 실행 결과가 대상 시스템을 반영하는지(--fs-root 없이 돌 때만)."""
    return ctx.fs_root in ("/", "")


def read_text(path, limit=1 << 20):
    try:
        with open(path, "rb") as f:
            return f.read(limit).decode("utf-8", "replace")
    except OSError:
        return None


def passwd_entries(ctx):
    res = []
    for line in (read_text(R(ctx, "/etc/passwd")) or "").splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and parts[2].isdigit():
            res.append({"name": parts[0], "uid": int(parts[2]), "gid": parts[3],
                        "home": parts[5], "shell": parts[6]})
    return res


def homes(ctx):
    seen, res = set(), []
    for e in passwd_entries(ctx):
        h = e["home"].rstrip("/") or "/"
        if h in NO_HOME or h in seen:
            continue
        if os.path.isdir(R(ctx, h)):
            seen.add(h)
            res.append((e["name"], R(ctx, h)))
    for p in sorted(os.listdir(R(ctx, "/home"))) if os.path.isdir(R(ctx, "/home")) else []:
        full = os.path.join(R(ctx, "/home"), p)
        if os.path.isdir(full) and "/home/" + p not in seen:
            res.append((p, full))
    return res


def _cmds(ctx, d, cmds, timeout=600):
    for argv, name in cmds:
        if os.path.isabs(argv[0]) or shutil.which(argv[0]):
            ctx.run(argv, d + name, timeout=timeout)


def copy_paths(ctx, paths, category, **kw):
    for p in paths:
        rp = R(ctx, p)
        if os.path.isdir(rp) and not os.path.islink(rp):
            ctx.copy_tree(rp, category, **kw)
        elif os.path.lexists(rp):
            ctx.copy(rp, category, **kw)


# ---------------------------------------------------------------- /proc 해석

def _boot_time():
    for line in (read_text("/proc/stat") or "").splitlines():
        if line.startswith("btime "):
            return int(line.split()[1])
    return None


def processes():
    """/proc/<pid> 정보 목록."""
    btime = _boot_time()
    try:
        hz = os.sysconf("SC_CLK_TCK")
    except (ValueError, OSError, AttributeError):
        hz = 100
    res = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        base = "/proc/" + name
        st = read_text(base + "/stat")
        if not st:
            continue
        comm = st[st.find("(") + 1:st.rfind(")")]
        rest = st[st.rfind(")") + 2:].split()
        p = {"pid": int(name), "comm": comm, "state": rest[0] if rest else "",
             "ppid": int(rest[1]) if len(rest) > 1 else None, "start": None,
             "uid": None, "exe": "", "exe_deleted": False, "cwd": "", "cmdline": ""}
        if btime and len(rest) > 19:
            p["start"] = core.ts_iso(btime + int(rest[19]) / float(hz))
        for line in (read_text(base + "/status") or "").splitlines():
            if line.startswith("Uid:"):
                p["uid"] = int(line.split()[1])
                break
        try:
            with open(base + "/cmdline", "rb") as f:
                p["cmdline"] = f.read(65536).replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except OSError:
            pass
        for key in ("exe", "cwd"):
            try:
                p[key] = os.readlink(base + "/" + key)
            except OSError:
                pass
        if p["exe"].endswith(" (deleted)"):
            p["exe_deleted"] = True
        res.append(p)
    return sorted(res, key=lambda x: x["pid"])


def _one_line(text, limit=200):
    """로그 한 줄에 맞춘다(셸 스크립트를 통째로 넘긴 명령줄은 줄바꿈을 품고 있다)."""
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    return text if len(text) <= limit else text[:limit] + "…"


def _socket_owners():
    owners = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        fd_dir = "/proc/%s/fd" % name
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                link = os.readlink(fd_dir + "/" + fd)
            except OSError:
                continue
            if link.startswith("socket:["):
                owners.setdefault(link[8:-1], set()).add(int(name))
    return owners


def _addr(hexaddr, v6):
    ip, port = hexaddr.split(":")
    raw = bytes.fromhex(ip)
    if v6:
        raw = b"".join(struct.pack("<I", struct.unpack(">I", raw[i:i + 4])[0]) for i in range(0, 16, 4))
        return socket.inet_ntop(socket.AF_INET6, raw), int(port, 16)
    return socket.inet_ntoa(raw[::-1]), int(port, 16)


def sockets():
    owners = _socket_owners()
    rows = []
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        text = read_text("/proc/net/" + proto, limit=64 << 20)
        if not text:
            continue
        for line in text.splitlines()[1:]:
            f = line.split()
            if len(f) < 10:
                continue
            try:
                la, lp = _addr(f[1], proto.endswith("6"))
                ra, rp = _addr(f[2], proto.endswith("6"))
            except (ValueError, OSError, struct.error):
                continue
            state = TCP_STATES.get(f[3], f[3]) if proto.startswith("tcp") else ("LISTEN" if f[3] == "07" else f[3])
            rows.append([proto, la, lp, ra, rp, state, f[7], f[9],
                         " ".join(str(x) for x in sorted(owners.get(f[9], ())))])
    return rows


# ---------------------------------------------------------------- 모듈

@module(OS, "memory", "물리 메모리 덤프 (avml, --memory)", level="quick", order=0, admin=True)
def memory(ctx):
    if not native(ctx):
        ctx.error("--fs-root 모드에서는 메모리 덤프를 하지 않음")
        return
    import platform
    tool = ctx.tool("avml-aarch64" if platform.machine() in ("aarch64", "arm64") else "avml")
    if not tool:
        ctx.error("메모리 덤프 도구 없음: tools/linux/avml(x86_64) 또는 avml-aarch64 를 두세요")
        return
    dest = ctx.path("memory/memory.lime")
    usage = (ctx.capture([tool, "--help"], merge_stderr=True) or b"").decode("utf-8", "replace")
    # avml 0.15 이후는 `avml acquire <파일>`, 그 전은 `avml <파일>`
    argv = [tool, "acquire", dest] if "acquire" in usage else [tool, dest]
    rc = ctx.run(argv, "logs/memory.txt", timeout=4 * 3600)
    if not ctx.dry_run and (not os.path.exists(dest) or os.path.getsize(dest) == 0):
        ctx.error("메모리 덤프 실패(rc=%s) — logs/memory.txt.stderr 확인. 컨테이너·커널 잠금(lockdown)이면 불가" % rc)
        return
    ctx.record_external(dest, "physical memory", "avml")


@module(OS, "environment", "실행 환경 판별(컨테이너·쿠버네티스 여부, 권한)", level="quick", order=5)
def environment(ctx):
    ind = []
    for p in ("/.dockerenv", "/run/.containerenv"):
        if os.path.exists(p):
            ind.append(p)
    cg = read_text("/proc/1/cgroup") or ""
    for key in ("docker", "kubepods", "containerd", "libpod", "lxc"):
        if key in cg:
            ind.append("cgroup:" + key)
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        ind.append("env:KUBERNETES_SERVICE_HOST")
    status = read_text("/proc/self/status") or ""
    caps = dict(l.split(":\t", 1) for l in status.splitlines() if l.startswith("Cap") and ":\t" in l)
    info = {
        "container": bool(ind),
        "indicators": ind,
        "fs_root": ctx.fs_root,
        "euid": os.geteuid(),
        "capabilities": caps,
        "pid1_cmdline": (read_text("/proc/1/cmdline") or "").replace("\0", " ").strip(),
        "cgroup": cg.strip().splitlines()[:20],
        "kubernetes_env": sorted(k for k in os.environ if k.startswith("KUBERNETES_")),
    }
    ctx.write_json("system/environment.json", info)
    if ind:
        ctx.info("컨테이너 환경으로 보임: %s", ", ".join(ind))


@module(OS, "volatile", "프로세스(/proc)·소켓·세션·커널 모듈 등 휘발성 정보", level="quick", order=10)
def volatile(ctx):
    users = dict((e["uid"], e["name"]) for e in passwd_entries(ctx))
    procs = processes()
    hashed = {}     # (dev, inode) → sha256: 같은 실행 파일을 여러 번 읽지 않는다
    fh, w = ctx.csv_writer("volatile/processes.csv",
                           ["pid", "ppid", "uid", "user", "state", "start", "comm", "exe", "exe_deleted",
                            "exe_sha256", "suspicious", "cwd", "cmdline"])
    try:
        for p in procs:
            exe_link = "/proc/%d/exe" % p["pid"]
            sha = ""
            suspicious = p["exe_deleted"] or p["exe"].startswith("/memfd:") or any(
                p["exe"].startswith(t + "/") for t in TMP_DIRS)
            # sh /tmp/x.sh 처럼 인터프리터로 돌리면 exe 는 정상이므로 명령줄도 본다(스크립트 본문은 hashes 모듈이 수집)
            reason = "exe" if suspicious else ""
            if not reason and any(tok.startswith(t + "/") for tok in p["cmdline"].split() for t in TMP_DIRS):
                reason = "cmdline"
            try:
                st = os.stat(exe_link)
                key = (st.st_dev, st.st_ino)
                if key not in hashed:
                    hashed[key] = core.hash_file(exe_link)[0]
                sha = hashed[key]
            except OSError:
                pass
            w.writerow([p["pid"], p["ppid"], p["uid"], users.get(p["uid"], ""), p["state"], p["start"],
                        p["comm"], p["exe"], p["exe_deleted"], sha, reason, p["cwd"], p["cmdline"]])
            if reason == "cmdline":
                ctx.warn("임시 폴더 경로로 실행된 프로세스 pid=%d cmdline=%s", p["pid"], _one_line(p["cmdline"]))
            if suspicious:
                ctx.warn("의심 프로세스 pid=%d exe=%s", p["pid"], _one_line(p["exe"]))
                ctx.copy(exe_link, "processes", follow=True, max_size=0,
                         name="pid%d_%s" % (p["pid"], os.path.basename(p["exe"].replace(" (deleted)", ""))),
                         note="실행 파일=%s cmdline=%s" % (p["exe"], p["cmdline"][:500]))
                for f in ("maps", "status", "cmdline", "mountinfo"):
                    ctx.copy("/proc/%d/%s" % (p["pid"], f), "processes", max_size=0,
                             name="pid%d_%s" % (p["pid"], f))
    finally:
        fh.close()
    fh, w = ctx.csv_writer("volatile/sockets.csv",
                           ["proto", "local_addr", "local_port", "remote_addr", "remote_port", "state",
                            "uid", "inode", "pids"])
    try:
        for row in sockets():
            w.writerow(row)
    finally:
        fh.close()
    _cmds(ctx, "volatile/", [
        (["ps", "auxwwf"], "ps_auxwwf.txt"),
        (["ss", "-tunapW"], "ss.txt"),
        (["netstat", "-tunap"], "netstat.txt"),
        (["ip", "addr"], "ip_addr.txt"),
        (["ip", "route"], "ip_route.txt"),
        (["ip", "neigh"], "ip_neigh.txt"),
        (["w"], "w.txt"),
        (["who", "-a"], "who.txt"),
        (["lsmod"], "lsmod.txt"),
        (["uptime"], "uptime.txt"),
    ])
    if ctx.at_least("standard"):
        _cmds(ctx, "volatile/", [(["lsof", "-nP", "-i"], "lsof_network.txt")])
    for p in ("/proc/mounts", "/proc/net/route", "/proc/net/arp", "/proc/modules", "/proc/cmdline",
              "/proc/version", "/proc/loadavg", "/proc/net/unix"):
        ctx.copy(p, "proc", max_size=0, follow=True)   # /proc/mounts 는 self/mounts 링크
    if native(ctx) and ctx.at_least("standard"):
        _cmds(ctx, "volatile/", [
            (["iptables-save"], "iptables_save.txt"),
            (["nft", "list", "ruleset"], "nft_ruleset.txt"),
            (["docker", "ps", "-a", "--no-trunc"], "docker_ps.txt"),
            (["docker", "images", "--digests", "--no-trunc"], "docker_images.txt"),
            (["crictl", "ps", "-a"], "crictl_ps.txt"),
        ])


def _redacted_shadow(text):
    out = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        h = parts[1]
        if h not in ("", "*", "!", "!!", "x", "!*"):
            locked = h.startswith("!")
            alg = h.lstrip("!").split("$")[1] if h.lstrip("!").startswith("$") else "des?"
            parts[1] = "%s<redacted:%s>" % ("!" if locked else "", alg)
        out.append(":".join(parts))
    return "\n".join(out) + "\n"


@module(OS, "system", "시스템·계정 정보(passwd, 가려진 shadow, 로그인 기록, 패키지 목록)", level="quick", order=30)
def system(ctx):
    copy_paths(ctx, ["/etc/os-release", "/etc/hostname", "/etc/passwd", "/etc/group", "/etc/sudoers",
                     "/etc/sudoers.d", "/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/fstab",
                     "/etc/timezone", "/etc/localtime"], "system", max_size=0)
    shadow = read_text(R(ctx, "/etc/shadow"))
    if shadow is not None:   # 비밀번호 해시는 남기지 않고 알고리즘·잠금 여부만 남긴다
        ctx.write_text("system/shadow_redacted.txt", _redacted_shadow(shadow))
    for p in ("/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog", "/var/run/utmp", "/run/utmp"):
        if os.path.exists(R(ctx, p)):
            ctx.copy(R(ctx, p), "system/login_records")
    copy_paths(ctx, ["/var/lib/dpkg/status", "/lib/apk/db/installed"], "system/packages", max_size=0)
    if native(ctx):
        _cmds(ctx, "system/", [
            (["uname", "-a"], "uname.txt"),
            (["hostname"], "hostname.txt"),
            (["id"], "id.txt"),
            (["timedatectl"], "timedatectl.txt"),
            (["last", "-Faiw"], "last.txt"),
            (["lastb", "-Faiw"], "lastb.txt"),
            (["lastlog"], "lastlog.txt"),
            (["df", "-h"], "df.txt"),
            (["lsblk", "-f"], "lsblk.txt"),
            (["rpm", "-qa", "--last"], "rpm_qa.txt"),
            (["getent", "passwd"], "getent_passwd.txt"),
        ])


@module(OS, "persistence", "자동 실행(cron, systemd, init, 셸 설정, ld.so.preload, PAM, SSH 키)", level="quick", order=40)
def persistence(ctx):
    copy_paths(ctx, [
        "/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
        "/etc/cron.monthly", "/etc/anacrontab", "/var/spool/cron", "/etc/crontabs", "/var/spool/at", "/etc/at.allow",
        "/etc/at.deny", "/etc/systemd/system", "/etc/systemd/user", "/run/systemd/system",
        "/etc/init.d", "/etc/rc.local", "/etc/rc.d/rc.local", "/etc/inittab",
        "/etc/profile", "/etc/profile.d", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zsh", "/etc/environment",
        "/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
        "/etc/pam.d", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d", "/etc/update-motd.d",
        "/etc/udev/rules.d", "/etc/xdg/autostart", "/etc/modules", "/etc/modules-load.d", "/etc/modprobe.d",
    ], "persistence")
    if os.path.exists(R(ctx, "/etc/ld.so.preload")):
        ctx.warn("/etc/ld.so.preload 가 있습니다 — 루트킷이 자주 쓰는 위치이니 확인하세요")
    for name, home in homes(ctx):
        for f in RC_FILES:
            p = os.path.join(home, f)
            if os.path.isfile(p):
                ctx.copy(p, "persistence/user_rc")
        for d in (".config/autostart", ".config/systemd/user"):
            if os.path.isdir(os.path.join(home, d)):
                ctx.copy_tree(os.path.join(home, d), "persistence/user_autostart")
    ctx.file_listing("persistence/systemd_units_vendor.csv",
                     [R(ctx, "/lib/systemd/system"), R(ctx, "/usr/lib/systemd/system")], hash_files=True)
    ctx.file_listing("persistence/pam_modules.csv",
                     [R(ctx, p) for p in ("/lib/security", "/lib64/security", "/usr/lib/security",
                                          "/usr/lib64/security", "/lib/x86_64-linux-gnu/security",
                                          "/usr/lib/x86_64-linux-gnu/security", "/lib/aarch64-linux-gnu/security")],
                     hash_files=True)
    if native(ctx):
        _cmds(ctx, "persistence/", [
            (["systemctl", "list-unit-files", "--no-pager"], "systemctl_unit_files.txt"),
            (["systemctl", "list-units", "--all", "--no-pager"], "systemctl_units.txt"),
            (["systemctl", "list-timers", "--all", "--no-pager"], "systemctl_timers.txt"),
        ])


@module(OS, "logs", "로그(/var/log, journal 텍스트, full이면 journal 원본)", level="quick", order=50)
def logs(ctx):
    ctx.copy_tree(R(ctx, "/var/log"), "logs/var_log", exclude_names=("journal",))
    if native(ctx) and shutil.which("journalctl"):
        argv = ["journalctl", "--no-pager", "-o", "short-iso-precise", "--since",
                ctx.log_since.astimezone().strftime("%Y-%m-%d %H:%M:%S")]
        if ctx.until:
            argv += ["--until", ctx.until.astimezone().strftime("%Y-%m-%d %H:%M:%S")]
        ctx.run(argv, "logs/journal.txt", timeout=3600)
        ctx.run(["journalctl", "--list-boots", "--no-pager"], "logs/journal_boots.txt")
    if ctx.at_least("full"):
        ctx.copy_tree(R(ctx, "/var/log/journal"), "logs/journal_raw", max_size=0)


@module(OS, "user_activity", "사용자 흔적(셸·도구 기록, 웹 루트 목록)", level="quick", order=80)
def user_activity(ctx):
    for name, home in homes(ctx):
        for f in HISTORY_FILES:
            p = os.path.join(home, f)
            if os.path.isfile(p):
                ctx.copy(p, "user/history", max_size=0)
        ctx.file_listing("user/home_%s.csv" % core.safe_component(name), [home], max_depth=1, hash_files=True)
    for web in ("/var/www", "/srv", "/usr/share/nginx/html", "/opt"):
        if os.path.isdir(R(ctx, web)) and ctx.at_least("standard"):
            ctx.file_listing("user/web_%s.csv" % core.safe_component(web.strip("/").replace("/", "_")),
                             [R(ctx, web)], hash_files=True, exclude_names=("node_modules", ".git"))


def _pick_exec(category):
    def pick(path, st, kind):
        if kind in ("elf", "script"):
            return category
        return None
    return pick


@module(OS, "hashes", "임시 폴더(/tmp, /var/tmp, /dev/shm) 해시 목록과 ELF·스크립트 수집", level="quick", order=110)
def hashes(ctx):
    roots = [R(ctx, d) for d in TMP_DIRS]
    n = ctx.file_listing("hashes/tmp_dirs.csv", roots, hash_files=True, collect=_pick_exec("suspicious/tmp"))
    ctx.info("임시 폴더 항목 %d개", n)


# 별도 파일시스템으로 마운트되는 경우가 많아 "/" 와 따로 도는 곳(xdev 라도 빠지지 않게)
EXTRA_ROOTS = ["/home", "/root", "/var", "/opt", "/srv", "/usr", "/boot", "/tmp", "/var/tmp", "/dev/shm"]


def _fs_roots(ctx):
    return [R(ctx, "/")] + [R(ctx, p) for p in EXTRA_ROOTS]


@module(OS, "suid", "SUID/SGID 파일 목록·해시", level="standard", order=115)
def suid(ctx):
    ctx.file_listing("sweep/suid_sgid.csv", _fs_roots(ctx), hash_files=True, xdev=True,
                     exclude=[R(ctx, p) for p in ("/proc", "/sys", "/run")],
                     only=lambda p, st: stat.S_ISREG(st.st_mode) and bool(st.st_mode & (stat.S_ISUID | stat.S_ISGID)))


@module(OS, "sweep", "시스템 바이너리 해시, 패키지 무결성 검증, 기간 내 변경 파일", level="full", order=120)
def sweep(ctx):
    ctx.file_listing("sweep/system_binaries.csv",
                     [R(ctx, p) for p in ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin",
                                          "/usr/local/sbin")], hash_files=True, hash_max=100 << 20)
    if native(ctx):
        _cmds(ctx, "sweep/", [(["dpkg", "--verify"], "dpkg_verify.txt"),
                              (["rpm", "-Va"], "rpm_verify.txt")], timeout=3600)
    if ctx.since is None:
        ctx.info("--since 가 없어 기간 타임라인은 건너뜀")
        return
    ctx.file_listing("sweep/timeline.csv", _fs_roots(ctx), xdev=True,
                     exclude=[R(ctx, p) for p in ("/proc", "/sys", "/run")],
                     only=lambda p, st: ctx.in_window(st),
                     collect=lambda p, st, kind: "period" if kind in ("elf", "script")
                     and ctx.in_window(st, ctime=False) else None)
