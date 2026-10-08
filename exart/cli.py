# -*- coding: utf-8 -*-
"""exart 명령행 진입점: 옵션 해석, 사전 점검, 모듈 실행, collection.json 마무리."""
import argparse
import datetime
import getpass
import io
import json
import logging
import os
import platform
import shutil
import socket
import sys
import time
import traceback

from . import core
from .core import iso, kst, now_utc, log

# 모듈 등록(import 시 core 레지스트리에 올라간다)
from . import windows, macos, linux  # noqa: F401

OS_NAMES = ("windows", "macos", "linux")


def detect_os():
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    return None


def is_admin(os_name):
    if os_name == "windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def default_tools_dir(os_name):
    if getattr(sys, "frozen", False):   # PyInstaller 단일 실행 파일: 실행 파일 옆 tools/<os>
        base = os.path.dirname(os.path.abspath(sys.executable))
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "tools", os_name)


def system_volumes(os_name):
    """조사 대상 시스템 볼륨(여기에 결과를 쓰면 미할당 영역을 덮어쓴다)."""
    if os_name == "windows":
        return [os.environ.get("SystemDrive", "C:") + "\\"]
    if os_name == "macos":
        return ["/", "/System/Volumes/Data"]
    return ["/"]


def same_volume_warning(out, os_name):
    probe = out
    while not os.path.exists(probe):
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    try:
        dev = os.stat(probe).st_dev
    except OSError:
        return None
    for v in system_volumes(os_name):
        try:
            if os.stat(v).st_dev == dev:
                return "결과 폴더가 시스템 볼륨(%s)에 있습니다. 미할당 영역의 삭제 흔적을 덮어쓸 수 있습니다." % v
        except OSError:
            continue
    return None


def host_info(os_name):
    info = {
        "hostname": socket.gethostname(),
        "os": os_name,
        # platform.platform() 은 PyInstaller 실행 파일에서 libc 버전을 잘못 읽으므로 직접 조합한다
        "platform": "%s-%s-%s" % (platform.system(), platform.release(), platform.machine()),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "frozen": bool(getattr(sys, "frozen", False)),
        "local_utc_offset": time.strftime("%z"),
        "local_tz": list(time.tzname),
    }
    try:
        info["fqdn"] = socket.getfqdn()
    except Exception:
        pass
    if os_name == "linux":
        try:
            with open("/etc/os-release", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        info["distribution"] = line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
    elif os_name == "macos":
        info["distribution"] = "macOS " + platform.mac_ver()[0]
    elif os_name == "windows":
        info["distribution"] = " ".join(x for x in platform.win32_ver()[:2] if x)
    return info


class _Fmt(logging.Formatter):
    def __init__(self, fmt, tz):
        logging.Formatter.__init__(self, fmt)
        self.tz = tz

    def formatTime(self, record, datefmt=None):
        dt = datetime.datetime.fromtimestamp(record.created, core.UTC).astimezone(self.tz)
        return dt.strftime("%Y-%m-%d %H:%M:%S") + (" KST" if self.tz is core.KST else "Z")


def setup_logging(out_dir, verbose):
    log.setLevel(logging.DEBUG)
    log.handlers[:] = []
    con = logging.StreamHandler(sys.stdout)
    con.setLevel(logging.DEBUG if verbose else logging.INFO)
    con.setFormatter(_Fmt("%(asctime)s %(levelname).1s %(message)s", core.KST))   # 화면: KST
    log.addHandler(con)
    if out_dir:
        fh = logging.FileHandler(os.path.join(out_dir, "exart.log"), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(_Fmt("%(asctime)s %(levelname)s %(message)s", core.UTC))   # 저장: UTC
        log.addHandler(fh)


def build_parser():
    p = argparse.ArgumentParser(
        prog="exart",
        description="사고 대응용 라이브 아티팩트 수집기 (Windows / macOS / Linux)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예) exart -o E:\\cases --case-id IR-2026-001 --profile standard --since 2026-10-01")
    p.add_argument("-o", "--out", help="결과를 둘 상위 폴더(외부 저장 장치 권장)")
    p.add_argument("--case-id", default="case", help="사건 ID(결과 폴더 이름에 쓰임)")
    p.add_argument("--profile", choices=core.PROFILES, default="standard",
                   help="quick: 휘발성·핵심만 / standard: 기본 / full: 전체 탐색·대용량 포함")
    p.add_argument("--modules", help="이 모듈만 실행(쉼표 구분). --list-modules 로 확인")
    p.add_argument("--skip", help="뺄 모듈(쉼표 구분)")
    p.add_argument("--memory", action="store_true", help="메모리 덤프(tools/<os>에 도구 필요)")
    p.add_argument("--since", help="조사 기간 시작(KST, 끝에 Z면 UTC). 로그 조회와 기간 내 파일 수집에 사용")
    p.add_argument("--until", help="조사 기간 끝(기본: 지금)")
    p.add_argument("--days", type=int, default=30, help="--since 가 없을 때 로그 조회 기간(일, 기본 30)")
    p.add_argument("--max-file-size", default="20M", help="파일 하나당 복사 상한(기본 20M, 0이면 제한 없음)")
    p.add_argument("--tools-dir", help="외부 도구 폴더(기본: tools/<os>)")
    p.add_argument("--fs-root", default="/",
                   help="(Linux) 대상 파일시스템 루트. kubectl debug 로 붙었을 때 /proc/<PID>/root")
    p.add_argument("--allow-same-volume", action="store_true", help="시스템 볼륨에 결과를 써도 진행")
    p.add_argument("--zip", action="store_true", help="끝나면 결과 폴더를 zip으로 묶음")
    p.add_argument("--dry-run", action="store_true", help="실제로 복사·실행하지 않고 계획만 기록")
    p.add_argument("-y", "--yes", action="store_true", help="시작 확인을 묻지 않음")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--list-modules", action="store_true", help="모듈 목록을 보여 주고 끝냄")
    p.add_argument("--verify", metavar="결과폴더", help="수집 결과 폴더의 해시를 대조하고 모듈별 결과를 요약")
    p.add_argument("--os", choices=OS_NAMES, help="(--list-modules 용) 다른 OS의 모듈 보기")
    p.add_argument("--version", action="version", version="exart " + core.VERSION)
    return p


def list_modules(os_name):
    print("%s 모듈 (실행 순서)" % os_name)
    print("  %-22s %-9s %-6s %s" % ("이름", "프로필", "관리자", "설명"))
    for m in core.modules_for(os_name):
        print("  %-22s %-9s %-6s %s" % (m.name, m.level, "필요" if m.admin else "", m.title))
    print("\n  quick ⊂ standard ⊂ full. memory 는 --memory 를 줘야 실행됨.")


def fix_stdio():
    """콘솔 인코딩이 한글을 못 쓰면(영문 cp1252, 일본어 cp932 등) UTF-8로 바꾸고 못 쓰는 글자는 대체한다."""
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name)
        if stream is None:
            continue
        try:
            "한글".encode(stream.encoding or "ascii")
            continue
        except (UnicodeEncodeError, LookupError):
            pass
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:      # Python 3.6
            setattr(sys, name, io.TextIOWrapper(stream.buffer, encoding="utf-8", errors="replace",
                                                line_buffering=True))


def main(argv=None):
    fix_stdio()
    args = build_parser().parse_args(argv)
    os_name = detect_os()

    if args.verify:
        from .verify import verify
        return verify(args.verify)
    if args.list_modules:
        list_modules(args.os or os_name or "linux")
        return 0
    if os_name is None:
        print("지원하지 않는 OS: %s" % sys.platform)
        return 2
    if not args.out:
        print("-o/--out 으로 결과 폴더를 지정하세요(외부 저장 장치 권장).")
        return 2
    if args.fs_root != "/" and os_name != "linux":
        print("--fs-root 는 Linux에서만 씁니다.")
        return 2

    try:
        since = core.parse_time(args.since) if args.since else None
        until = core.parse_time(args.until) if args.until else None
        max_size = core.parse_size(args.max_file_size)
        only = [x.strip() for x in args.modules.split(",")] if args.modules else None
        skip = [x.strip() for x in args.skip.split(",")] if args.skip else None
        mods = core.modules_for(os_name, args.profile, only=only, skip=skip)
    except ValueError as e:
        print(str(e))
        return 2
    if not args.memory and not only:
        mods = [m for m in mods if m.name != "memory"]
    elif args.memory and "memory" not in [m.name for m in mods]:
        mods = core.modules_for(os_name, only=["memory"]) + mods

    started = now_utc()
    host = socket.gethostname().split(".")[0] or "host"
    folder = "%s_%s_%s" % (core.safe_component(args.case_id), core.safe_component(host),
                           started.strftime("%Y%m%dT%H%M%SZ"))
    out_dir = os.path.join(os.path.abspath(args.out), folder)
    admin = is_admin(os_name)
    vol_warn = same_volume_warning(out_dir, os_name)
    tools_dir = os.path.abspath(args.tools_dir) if args.tools_dir else default_tools_dir(os_name)

    setup_logging(None, args.verbose)
    print("=" * 72)
    print(" exart %s — 라이브 아티팩트 수집 (%s)" % (core.VERSION, os_name))
    print("=" * 72)
    print(" 결과 폴더 : %s" % out_dir)
    print(" 프로필    : %s   메모리 덤프: %s   파일 상한: %s" % (
        args.profile, "예" if args.memory else "아니오", args.max_file_size))
    print(" 기간      : %s ~ %s" % (kst(since) if since else "(로그 %d일)" % args.days,
                                    kst(until) if until else "지금"))
    print(" 관리자    : %s" % ("예" if admin else "아니오 — 일부 아티팩트를 수집하지 못합니다"))
    print(" 모듈      : %s" % ", ".join(m.name for m in mods))
    probe = out_dir
    while not os.path.exists(probe) and os.path.dirname(probe) != probe:
        probe = os.path.dirname(probe)
    free = core.disk_free(probe)
    if free is not None:
        print(" 남은 공간 : %.1f GB" % (free / float(1 << 30)))
    if vol_warn:
        print("\n [경고] " + vol_warn)
        if not args.allow_same_volume and not args.dry_run:
            print(" 외부 저장 장치를 지정하거나, 의도한 것이면 --allow-same-volume 을 주세요.")
            return 3
    print(" 수집 결과에는 악성 실행 파일이 들어갈 수 있습니다. 분석은 격리 환경에서만 하세요.")
    if not args.yes:
        if not sys.stdin.isatty():
            print("대화형 터미널이 아니면 -y 로 확인을 생략해야 합니다.")
            return 2
        try:
            answer = input("\n 시작할까요? [y/N] ")
        except (KeyboardInterrupt, EOFError):
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            print(" 취소했습니다.")
            return 1

    os.makedirs(out_dir, exist_ok=True)
    setup_logging(out_dir, args.verbose)
    ctx = core.Context(out_dir, os_name, profile=args.profile, since=since, until=until,
                       max_size=max_size, dry_run=args.dry_run, tools_dir=tools_dir,
                       fs_root=args.fs_root)
    ctx.is_admin = admin
    ctx.log_since = since or (started - datetime.timedelta(days=args.days))

    results = []
    status = "completed"
    try:
        for m in mods:
            ctx.module = m.name
            rec = {"name": m.name, "title": m.title, "started_at": iso(now_utc())}
            if m.admin and not admin:
                ctx.warn("관리자 권한이 없어 일부만 수집될 수 있음")
            log.info("[%s] 시작 — %s", m.name, m.title)
            t0 = time.time()
            errs_before = ctx.stats["errors"]
            try:
                m.func(ctx)
                rec["status"] = "ok"
            except KeyboardInterrupt:
                rec["status"] = "interrupted"
                results.append(rec)
                raise
            except Exception as e:
                rec["status"] = "failed"
                rec["error"] = "%s: %s" % (type(e).__name__, e)
                ctx.error("모듈 실패", e)
                log.debug(traceback.format_exc())
            rec["ended_at"] = iso(now_utc())
            rec["duration_s"] = round(time.time() - t0, 1)
            rec["errors"] = ctx.stats["errors"] - errs_before
            results.append(rec)
            log.info("[%s] %s (%.1fs, 오류 %d)", m.name, rec["status"], rec["duration_s"], rec["errors"])
    except KeyboardInterrupt:
        status = "interrupted"
        log.warning("사용자가 중단함 — 지금까지 수집한 결과를 마무리합니다")
    finally:
        ctx.module = None
        ended = now_utc()
        ctx.close()
        for h in list(log.handlers):
            if isinstance(h, logging.FileHandler):
                h.close()
                log.removeHandler(h)
        sums_path, sums_sha = core.write_hash_list(ctx)
        summary = "%s %s 수집 %s: 파일 %d개(%.1f MB), 명령 %d회, 오류 %d건" % (
            host, os_name, status, ctx.stats["files"], ctx.stats["bytes"] / 1048576.0,
            ctx.stats["commands"], ctx.stats["errors"])
        doc = {
            "schema": core.SCHEMA,
            "package": None,
            "sha256": None,
            "tool": "exart",
            "tool_version": core.VERSION,
            "created_at": iso(ended),
            "summary": summary,
            "case_id": args.case_id,
            "status": status,
            "started_at": iso(started),
            "ended_at": iso(ended),
            "host": host_info(os_name),
            "operator": {"user": _user(), "is_admin": admin},
            "profile": args.profile,
            "options": {"memory": args.memory, "modules": only, "skip": skip,
                        "max_file_size": max_size, "fs_root": args.fs_root,
                        "dry_run": args.dry_run, "tools_dir": tools_dir,
                        "argv": sys.argv[1:] if argv is None else argv},
            "time_window": {"since": iso(since), "until": iso(until),
                            "log_since": iso(ctx.log_since)},
            "output_volume_warning": vol_warn,
            "modules": results,
            "stats": ctx.stats,
            "errors_sample": ctx.errors[:100],
            "contains_executables": ctx.stats["executables"] > 0,
            "handling": "결과에 악성 실행 파일이 있을 수 있음. 격리 환경에서만 풀고 분석할 것.",
            "integrity": {"hash_list": "SHA256SUMS", "hash_list_sha256": sums_sha},
        }
        with open(os.path.join(out_dir, "collection.json"), "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
        print("\n" + summary)
        print(" 결과    : %s" % out_dir)
        print(" SHA256SUMS sha256 = %s  (사건 기록에 적어 두세요)" % sums_sha)
        if args.zip and not args.dry_run:
            z = shutil.make_archive(out_dir, "zip", os.path.dirname(out_dir), folder)
            print(" zip     : %s\n zip sha256 = %s" % (z, core.hash_file(z)[0]))
    return 0 if status == "completed" else 130


def _user():
    try:
        return getpass.getuser()
    except Exception:
        return None


if __name__ == "__main__":
    sys.exit(main())
