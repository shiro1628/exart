# -*- coding: utf-8 -*-
"""exart 공통 코어.

결과 폴더, 명령 실행 기록(commands.jsonl), 파일 복사·해시(manifest.jsonl),
모듈 등록과 실행 순서를 맡는다. 대상 시스템에 설치 없이 돌도록 표준 라이브러리만
쓰고 Python 3.6 문법을 지킨다(dataclass, walrus, capture_output 금지).
"""
import datetime
import hashlib
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import time

VERSION = "2.0.0"
SCHEMA = "ir.exart.collection.v1"
PROFILES = ("quick", "standard", "full")
UTC = datetime.timezone.utc
KST = datetime.timezone(datetime.timedelta(hours=9), "KST")
CHUNK = 1024 * 1024
IS_WINDOWS = os.name == "nt"
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

log = logging.getLogger("exart")


# ---------------------------------------------------------------- 시간

def now_utc():
    return datetime.datetime.now(UTC)


def iso(dt):
    """UTC ISO 8601 문자열(저장용)."""
    if dt is None:
        return None
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def ts_iso(ts):
    if ts is None:
        return None
    try:
        return iso(datetime.datetime.fromtimestamp(ts, UTC))
    except (OverflowError, OSError, ValueError):
        return None


def kst(dt):
    """화면 표시용 KST 문자열."""
    return dt.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S KST")


def parse_time(text):
    """'2026-10-01', '2026-10-01 09:00' 등을 받는다. 끝에 Z가 없으면 KST로 본다."""
    text = text.strip()
    tz = KST
    if text.endswith("Z"):
        tz, text = UTC, text[:-1]
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.datetime.strptime(text, fmt)
        except ValueError:
            continue
        return dt.replace(tzinfo=tz).astimezone(UTC)
    raise ValueError("시간 형식을 알 수 없음: %r (예: 2026-10-01, 2026-10-01 09:00)" % text)


def parse_size(text):
    m = re.match(r"^\s*(\d+(?:\.\d+)?)\s*([KMGT]?)B?\s*$", str(text), re.I)
    if not m:
        raise ValueError("크기 형식을 알 수 없음: %r (예: 20M, 1G)" % text)
    mult = {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}[m.group(2).upper()]
    return int(float(m.group(1)) * mult)


# ---------------------------------------------------------------- 모듈 등록

class Module(object):
    def __init__(self, os_name, name, func, title, level, order, admin):
        self.os_name = os_name
        self.name = name
        self.func = func
        self.title = title
        self.level = level
        self.order = order
        self.admin = admin


_REGISTRY = []


def module(os_name, name, title, level="quick", order=50, admin=False):
    """수집 모듈 등록. level은 포함되는 최소 프로필, order는 실행 순서(작을수록 먼저, 휘발성 높은 것 먼저)."""
    if level not in PROFILES:
        raise ValueError(level)

    def deco(func):
        _REGISTRY.append(Module(os_name, name, func, title, level, order, admin))
        return func
    return deco


def modules_for(os_name, profile=None, only=None, skip=None):
    mods = [m for m in _REGISTRY if m.os_name == os_name]
    if only:
        unknown = set(only) - set(m.name for m in mods)
        if unknown:
            raise ValueError("없는 모듈: %s" % ", ".join(sorted(unknown)))
        mods = [m for m in mods if m.name in only]
    elif profile:
        limit = PROFILES.index(profile)
        mods = [m for m in mods if PROFILES.index(m.level) <= limit]
    if skip:
        mods = [m for m in mods if m.name not in skip]
    return sorted(mods, key=lambda m: m.order)


# ---------------------------------------------------------------- 파일 유틸

def sniff(head):
    """파일 앞부분으로 실행 파일·스크립트 여부를 판정한다."""
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                    b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macho"
    if head[:2] == b"#!":
        return "script"
    return None


_BAD_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')


def safe_component(name):
    """exFAT·NTFS 등 출력 매체에서 만들 수 없는 이름을 바꾼다(원래 경로는 manifest에 남는다)."""
    name = _BAD_CHARS.sub("_", name).rstrip(" .") or "_"
    if len(name.encode("utf-8")) > 200:
        digest = hashlib.sha1(name.encode("utf-8")).hexdigest()[:12]
        name = name[:80] + "~" + digest
    return name


def mangle(path):
    """원본 절대 경로를 결과 폴더 안의 상대 경로로 바꾼다. C:\\a\\b → C/a/b, /a/b → a/b"""
    p = path
    if p.startswith("\\\\?\\"):
        p = p[4:]
    p = p.replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/?(.*)$", p)
    if m:
        p = m.group(1).upper() + "/" + m.group(2)
    parts = [safe_component(x) for x in p.split("/") if x not in ("", ".", "..")]
    return "/".join(parts) or "_"


def long_path(path):
    if IS_WINDOWS and len(path) > 240 and not path.startswith("\\\\?\\"):
        return "\\\\?\\" + os.path.abspath(path)
    return path


# 읽는 순간 클라우드에서 내려받는 파일(OneDrive 온라인 전용, iCloud dataless). 수집이 대상 시스템과 네트워크를 건드리므로 읽지 않는다.
_WIN_OFFLINE = 0x00001000 | 0x00040000 | 0x00400000   # OFFLINE, RECALL_ON_OPEN, RECALL_ON_DATA_ACCESS
_MAC_DATALESS = 0x40000000                           # SF_DATALESS


def is_cloud_placeholder(st):
    if getattr(st, "st_file_attributes", 0) & _WIN_OFFLINE:
        return True
    return bool(getattr(st, "st_flags", 0) & _MAC_DATALESS)


def stat_meta(st):
    meta = {
        "size": st.st_size,
        "mode": oct(stat.S_IMODE(st.st_mode)),
        "mtime": ts_iso(st.st_mtime),
        "atime": ts_iso(st.st_atime),
        "ctime": ts_iso(st.st_ctime),
    }
    birth = getattr(st, "st_birthtime", None)
    if birth is not None:
        meta["birth"] = ts_iso(birth)
    if not IS_WINDOWS:
        meta["uid"] = st.st_uid
        meta["gid"] = st.st_gid
        meta["inode"] = st.st_ino
    return meta


def hash_file(path):
    """(sha256, md5, kind) 를 돌려준다. 읽지 못하면 OSError."""
    sha, md5 = hashlib.sha256(), hashlib.md5()
    kind = None
    with open(long_path(path), "rb") as f:
        first = True
        while True:
            buf = f.read(CHUNK)
            if not buf:
                break
            if first:
                kind = sniff(buf[:8])
                first = False
            sha.update(buf)
            md5.update(buf)
    return sha.hexdigest(), md5.hexdigest(), kind


def disk_free(path):
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return None


# ---------------------------------------------------------------- 수집 컨텍스트

class Context(object):
    """모듈이 쓰는 수집 도구 모음. 모든 결과는 out 아래에 쓰고 기록을 남긴다."""

    def __init__(self, out, os_name, profile="standard", since=None, until=None,
                 max_size=20 << 20, dry_run=False, tools_dir=None, fs_root="/",
                 exclude=()):
        self.out = os.path.abspath(out)
        self.os_name = os_name
        self.profile = profile
        self.since = since
        self.until = until
        self.max_size = max_size
        self.dry_run = dry_run
        self.tools_dir = tools_dir
        self.fs_root = fs_root
        self.module = None
        self.is_admin = False
        self.log_since = since
        self.stats = {"files": 0, "bytes": 0, "skipped": 0, "errors": 0,
                      "commands": 0, "executables": 0}
        self.errors = []
        self.hashed = {}            # out 기준 상대 경로 → sha256 (SHA256SUMS 재계산 생략용)
        self._copied = {}           # 원본 경로 → 결과 상대 경로 (중복 복사 방지)
        # 자기 자신(결과 폴더, 도구 폴더, 실행 파일)은 탐색에서 뺀다.
        self.self_paths = [self.out]
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.self_paths.append(here)
        if getattr(sys, "frozen", False):
            self.self_paths.append(os.path.dirname(os.path.abspath(sys.executable)))
        if tools_dir:
            self.self_paths.append(os.path.abspath(tools_dir))
        self.self_paths.extend(os.path.abspath(p) for p in exclude)
        os.makedirs(self.out, exist_ok=True)
        self._manifest = open(os.path.join(self.out, "manifest.jsonl"), "a", encoding="utf-8")
        self._commands = open(os.path.join(self.out, "commands.jsonl"), "a", encoding="utf-8")
        self._errors = open(os.path.join(self.out, "errors.jsonl"), "a", encoding="utf-8")

    # ---------- 기본

    def at_least(self, level):
        return PROFILES.index(self.profile) >= PROFILES.index(level)

    def path(self, rel):
        """결과 폴더 안 경로(부모 폴더 생성)."""
        p = os.path.join(self.out, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    def dir(self, rel):
        """결과 폴더 안 하위 폴더(생성해서 절대 경로를 돌려준다)."""
        p = os.path.join(self.out, *rel.strip("/").split("/"))
        os.makedirs(p, exist_ok=True)
        return p

    def rel(self, p):
        return os.path.relpath(p, self.out).replace(os.sep, "/")

    def close(self):
        for f in (self._manifest, self._commands, self._errors):
            try:
                f.close()
            except Exception:
                pass

    def _jsonl(self, fh, obj):
        fh.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")
        fh.flush()

    def info(self, msg, *args):
        log.info("[%s] " + msg, self.module or "-", *args)

    def warn(self, msg, *args):
        log.warning("[%s] " + msg, self.module or "-", *args)

    def error(self, msg, exc=None):
        text = msg if exc is None else "%s: %s" % (msg, exc)
        self.stats["errors"] += 1
        rec = {"module": self.module, "at": iso(now_utc()), "message": text}
        self.errors.append(rec)
        self._jsonl(self._errors, rec)
        log.debug("[%s] %s", self.module or "-", text)

    def tool(self, *names):
        """tools/<os>/ 의 번들 도구를 먼저 찾고, 없으면 PATH에서 찾는다."""
        for n in names:
            if self.tools_dir:
                p = os.path.join(self.tools_dir, n)
                if os.path.isfile(p):
                    return p
        for n in names:
            p = shutil.which(n)
            if p:
                return p
        return None

    # ---------- 결과 쓰기

    def write_text(self, rel, text):
        p = self.path(rel)
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        return p

    def write_json(self, rel, obj):
        p = self.path(rel)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=True)
        return p

    def csv_writer(self, rel, header):
        import csv
        p = self.path(rel)
        fh = open(p, "w", encoding="utf-8", newline="")
        w = csv.writer(fh)
        w.writerow(header)
        return fh, w

    # ---------- 명령 실행

    def run(self, argv, out, timeout=900, stdin=None, env=None, cwd=None):
        """명령을 실행하고 stdout을 out(결과 폴더 상대 경로)에 저장한다. 종료 코드를 돌려준다(실행 못 하면 None)."""
        argv = [str(a) for a in argv]
        rec = {"module": self.module, "argv": argv, "out": out, "started_at": iso(now_utc())}
        exe = argv[0]
        if not os.path.isabs(exe) and shutil.which(exe) is None:
            rec["status"] = "not_found"
            self._jsonl(self._commands, rec)
            self.error("명령 없음: %s" % exe)
            return None
        if self.dry_run:
            rec["status"] = "dry_run"
            self._jsonl(self._commands, rec)
            self.info("(dry-run) %s", " ".join(argv))
            return 0
        out_path = self.path(out)
        err_path = out_path + ".stderr"
        t0 = time.time()
        rc = None
        try:
            with open(out_path, "wb") as fo, open(err_path, "wb") as fe:
                kwargs = {"stdout": fo, "stderr": fe, "cwd": cwd, "env": env,
                          "stdin": subprocess.PIPE if stdin is not None else subprocess.DEVNULL}
                if IS_WINDOWS:
                    kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
                proc = subprocess.Popen(argv, **kwargs)
                try:
                    if stdin is not None:
                        data = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
                        proc.communicate(data, timeout=timeout)
                    else:
                        proc.wait(timeout=timeout)
                    rc = proc.returncode
                    rec["status"] = "ok" if rc == 0 else "error"
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    rc = proc.returncode
                    rec["status"] = "timeout"
                    self.error("시간 초과(%ss): %s" % (timeout, " ".join(argv)))
        except OSError as e:
            rec["status"] = "exec_error"
            rec["error"] = str(e)
            self.error("실행 실패: %s" % " ".join(argv), e)
        rec["rc"] = rc
        rec["ended_at"] = iso(now_utc())
        rec["duration_s"] = round(time.time() - t0, 3)
        if os.path.exists(err_path) and os.path.getsize(err_path) == 0:
            os.remove(err_path)
        if os.path.exists(out_path):
            try:
                sha, _, _ = hash_file(out_path)
                rec["sha256"] = sha
                rec["size"] = os.path.getsize(out_path)
                self.hashed[self.rel(out_path)] = sha
            except OSError:
                pass
        self.stats["commands"] += 1
        self._jsonl(self._commands, rec)
        return rc

    def capture(self, argv, timeout=120, stdin=None, merge_stderr=False, record=True):
        """출력을 파일로 남기지 않고 받아 온다(목록 조회 등 파싱용). 실패하면 None.
        record=False 는 파일마다 반복하는 조회(codesign 등)에서 commands.jsonl 이 부풀지 않게 한다."""
        argv = [str(a) for a in argv]
        rec = {"module": self.module, "argv": argv, "out": None, "started_at": iso(now_utc())}
        if not os.path.isabs(argv[0]) and shutil.which(argv[0]) is None:
            rec["status"] = "not_found"
            if record:
                self._jsonl(self._commands, rec)
            return None
        try:
            kwargs = {"stdout": subprocess.PIPE,
                      "stderr": subprocess.STDOUT if merge_stderr else subprocess.PIPE,
                      "stdin": subprocess.PIPE if stdin is not None else subprocess.DEVNULL}
            if IS_WINDOWS:
                kwargs["creationflags"] = 0x08000000
            proc = subprocess.Popen(argv, **kwargs)
            data = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
            out, _ = proc.communicate(data, timeout=timeout)
            rec["rc"] = proc.returncode
            rec["status"] = "ok" if proc.returncode == 0 else "error"
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            rec["status"] = "timeout"
            out = None
        except OSError as e:
            rec["status"] = "exec_error"
            rec["error"] = str(e)
            out = None
        rec["ended_at"] = iso(now_utc())
        if record:
            self.stats["commands"] += 1
            self._jsonl(self._commands, rec)
        return out

    # ---------- 파일 수집

    def logical(self, path):
        """fs_root(컨테이너 루트 등) 접두를 뗀 원래 경로."""
        if self.fs_root not in ("/", "") and path.startswith(self.fs_root):
            return "/" + path[len(self.fs_root):].lstrip("/")
        return path

    def copy(self, src, category, follow=False, max_size=None, record_failure=True,
             name=None, note=None):
        """파일 하나를 files/<category>/<원본 경로> 로 복사한다.

        원본 메타데이터(시간·권한)는 복사 전에 읽어 manifest에 남기고, 복사본에도
        mtime/atime을 되돌려 둔다. 읽으면서 SHA-256·MD5를 같이 계산한다.
        항상 manifest 항목(dict)을 돌려주고, status는 ok/skipped/error 중 하나다.
        """
        limit = self.max_size if max_size is None else max_size
        logical = self.logical(src)
        entry = {"module": self.module, "source": logical, "category": category,
                 "method": "copy", "collected_at": iso(now_utc())}
        if note:
            entry["note"] = note
        key = (os.path.normcase(os.path.abspath(src)), category)
        if key in self._copied:
            entry.update(status="skipped", reason="duplicate", dest=self._copied[key])
            return entry
        try:
            st = os.stat(long_path(src)) if follow else os.lstat(long_path(src))
        except OSError as e:
            entry.update(status="error", error=str(e))
            if record_failure:
                self._record(entry)
            return entry
        entry.update(stat_meta(st))
        if stat.S_ISLNK(st.st_mode):
            try:
                entry["link_target"] = os.readlink(src)
            except OSError:
                pass
            entry.update(status="skipped", reason="symlink")
            self._record(entry)
            return entry
        if not stat.S_ISREG(st.st_mode):
            entry.update(status="skipped", reason="not_regular_file")
            self._record(entry)
            return entry
        if is_cloud_placeholder(st):
            entry.update(status="skipped", reason="cloud_placeholder")
            self.stats["skipped"] += 1
            self._record(entry)
            return entry
        if limit and st.st_size > limit:
            entry.update(status="skipped", reason="too_large")
            self.stats["skipped"] += 1
            self._record(entry)
            return entry
        dest_rel = self._unique_dest("files/%s/%s" % (category, mangle(name or logical)))
        entry["dest"] = dest_rel
        if self.dry_run:
            entry["status"] = "dry_run"
            self._record(entry)
            return entry
        dest = self.path(dest_rel)
        sha, md5 = hashlib.sha256(), hashlib.md5()
        kind = None
        size = 0
        try:
            with open(long_path(src), "rb") as fi, open(long_path(dest), "wb") as fo:
                first = True
                while True:
                    buf = fi.read(CHUNK)
                    if not buf:
                        break
                    if first:
                        kind = sniff(buf[:8])
                        first = False
                    sha.update(buf)
                    md5.update(buf)
                    fo.write(buf)
                    size += len(buf)
        except OSError as e:
            try:
                os.remove(dest)
            except OSError:
                pass
            entry.update(status="error", error=str(e))
            entry.pop("dest", None)
            if record_failure:
                self._record(entry)
            return entry
        try:
            os.utime(long_path(dest), (st.st_atime, st.st_mtime))
        except OSError:
            pass
        entry.update(status="ok", sha256=sha.hexdigest(), md5=md5.hexdigest(),
                     copied_size=size, kind=kind)
        self._copied[key] = dest_rel
        self.hashed[dest_rel] = entry["sha256"]
        self.stats["files"] += 1
        self.stats["bytes"] += size
        if kind in ("pe", "elf", "macho"):
            self.stats["executables"] += 1
        self._record(entry)
        return entry

    def _unique_dest(self, rel):
        """원본이 달라도 결과 이름이 같아질 수 있다(대소문자 무시 매체, 특수문자 치환).
        덮어쓰지 않도록 이미 있으면 ~2, ~3 을 붙인다. manifest 에 원래 경로가 남는다."""
        if self.dry_run or not os.path.exists(long_path(os.path.join(self.out, *rel.split("/")))):
            return rel
        base, ext = os.path.splitext(rel)
        n = 2
        while os.path.exists(long_path(os.path.join(self.out, *("%s~%d%s" % (base, n, ext)).split("/")))):
            n += 1
        return "%s~%d%s" % (base, n, ext)

    def record_external(self, dest, source, method, note=None, meta=None):
        """다른 도구(reg save, esentutl 등)가 만든 파일을 manifest에 올린다. 없으면 아무것도 하지 않는다."""
        if not os.path.exists(dest):
            return None
        entry = {"module": self.module, "source": source, "dest": self.rel(dest),
                 "method": method, "collected_at": iso(now_utc())}
        if meta:
            entry.update(meta)
        if note:
            entry["note"] = note
        try:
            if entry["dest"] in self.hashed:      # run()이 이미 해시한 출력(대용량 $MFT 등)은 다시 읽지 않는다
                sha, md5 = self.hashed[entry["dest"]], None
                with open(long_path(dest), "rb") as f:
                    kind = sniff(f.read(8))
            else:
                sha, md5, kind = hash_file(dest)
            entry.update(status="ok", sha256=sha, md5=md5, kind=kind,
                         copied_size=os.path.getsize(dest))
            self.hashed[entry["dest"]] = sha
            self.stats["files"] += 1
            self.stats["bytes"] += entry["copied_size"]
        except OSError as e:
            entry.update(status="error", error=str(e))
        self._record(entry)
        return entry

    def _record(self, entry):
        if entry.get("status") == "error":
            self.error("수집 실패: %s" % entry.get("source"), entry.get("error"))
        self._jsonl(self._manifest, entry)

    def copy_glob(self, patterns, category, **kw):
        import glob
        n = 0
        for pat in patterns:
            for p in sorted(glob.glob(pat)):
                if os.path.isfile(p):
                    if self.copy(p, category, **kw).get("status") == "ok":
                        n += 1
        return n

    def copy_tree(self, root, category, max_depth=None, match=None, exclude_names=(), **kw):
        """root 아래 파일을 복사한다. match(path)가 주어지면 True인 것만."""
        n = 0
        for p, st in self.walk([root], exclude_names=exclude_names, max_depth=max_depth):
            if stat.S_ISREG(st.st_mode) and (match is None or match(p)):
                if self.copy(p, category, **kw).get("status") == "ok":
                    n += 1
        return n

    # ---------- 탐색

    def _excluded(self, path, prefixes):
        p = os.path.normcase(os.path.abspath(path))
        for x in prefixes:
            if p == x or p.startswith(x.rstrip(os.sep) + os.sep):
                return True
        return False

    def walk(self, roots, exclude=(), exclude_names=(), xdev=False, max_depth=None):
        """(경로, lstat)를 낸다. 링크·정션은 따라가지 않고, 결과 폴더와 도구 폴더는 건너뛴다.
        xdev 는 루트마다 그 루트의 파일시스템 안에서만 돈다. 앞 루트에서 이미 돈 하위 루트는 다시 돌지 않는다."""
        prefixes = [os.path.normcase(os.path.abspath(p)) for p in list(exclude) + self.self_paths]
        names = set(n.lower() for n in exclude_names)
        done = []           # (경로, 장치): 이미 돈 루트
        for root in roots:
            try:
                rst = os.lstat(root)
            except OSError:
                continue
            if not stat.S_ISDIR(rst.st_mode) or self._excluded(root, prefixes):
                continue
            key = os.path.normcase(os.path.abspath(root))
            covered = False
            for k, dev in done:
                inside = key == k or key.startswith(k.rstrip(os.sep) + os.sep)
                if inside and (not xdev or dev == rst.st_dev):
                    covered = True
                    break
            if covered:
                continue
            done.append((key, rst.st_dev))
            stack = [(root, 0)]
            while stack:
                d, depth = stack.pop()
                try:
                    it = os.scandir(long_path(d))
                except OSError:
                    continue
                with it:
                    for e in it:
                        p = os.path.join(d, e.name)
                        try:
                            st = e.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        if getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
                            yield p, st     # 정션·심볼릭 링크: 목록에만 올리고 들어가지 않는다
                            continue
                        if stat.S_ISDIR(st.st_mode):
                            if e.name.lower() in names or self._excluded(p, prefixes):
                                continue
                            if xdev and st.st_dev != rst.st_dev:
                                continue
                            yield p, st
                            if (max_depth is None or depth < max_depth) and depth < 64:
                                stack.append((p, depth + 1))
                        else:
                            yield p, st

    def file_listing(self, rel_csv, roots, hash_files=False, hash_max=None, collect=None,
                     exclude=(), exclude_names=(), xdev=False, max_depth=None, only=None):
        """roots 아래 항목을 CSV로 남긴다(바디파일 대용).

        hash_files: 일반 파일 해시 계산(hash_max 이하만)
        collect(path, st, kind) → 카테고리 문자열을 돌려주면 그 파일을 복사한다.
        only(path, st) → False 면 목록에서 뺀다.
        반환: 기록한 행 수
        """
        if self.dry_run:
            self.info("(dry-run) 목록: %s", ", ".join(roots))
            return 0
        hash_max = self.max_size if hash_max is None else hash_max
        fh, w = self.csv_writer(rel_csv, ["path", "type", "size", "mode", "uid", "gid",
                                          "mtime", "atime", "ctime", "birth",
                                          "sha256", "md5", "kind", "link_target"])
        n = 0
        try:
            for p, st in self.walk(roots, exclude=exclude, exclude_names=exclude_names,
                                   xdev=xdev, max_depth=max_depth):
                if only is not None and not only(p, st):
                    continue
                m = stat_meta(st)
                if stat.S_ISDIR(st.st_mode):
                    t = "d"
                elif stat.S_ISLNK(st.st_mode):
                    t = "l"
                elif stat.S_ISREG(st.st_mode):
                    t = "f"
                else:
                    t = "o"
                sha = md5 = kind = link = ""
                if t == "f" and is_cloud_placeholder(st):
                    t = "cloud"     # 목록에만 남기고 읽지 않는다
                if t == "l" or getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
                    try:
                        link = os.readlink(p)
                    except (OSError, ValueError):
                        pass
                if t == "f" and (hash_files or collect) and (not hash_max or st.st_size <= hash_max):
                    try:
                        sha, md5, kind = hash_file(p)
                        kind = kind or ""
                    except OSError:
                        pass
                w.writerow([self.logical(p), t, st.st_size, m["mode"], m.get("uid", ""),
                            m.get("gid", ""), m["mtime"], m["atime"], m["ctime"],
                            m.get("birth", ""), sha, md5, kind, link])
                n += 1
                if collect is not None and t == "f":
                    cat = collect(p, st, kind or None)
                    if cat:
                        self.copy(p, cat)
        finally:
            fh.close()
        return n

    def in_window(self, st, ctime=True):
        """since/until 안에 수정·변경·생성된 항목인지.

        ctime=False: 수집 판단용. 컨테이너 이미지는 풀린 시각이 ctime 이라 전부 걸리므로
        mtime·생성 시각만 본다(목록에는 ctime 기준도 남겨 시간 조작 흔적을 볼 수 있게 한다)."""
        if self.since is None:
            return False
        lo = self.since.timestamp()
        hi = self.until.timestamp() if self.until else time.time() + 86400
        times = [st.st_mtime] + ([st.st_ctime] if ctime else [])
        birth = getattr(st, "st_birthtime", None)
        if birth is not None:
            times.append(birth)
        return any(lo <= t <= hi for t in times)


# ---------------------------------------------------------------- 마무리

def write_hash_list(ctx, name="SHA256SUMS"):
    """결과 폴더의 모든 파일 해시 목록을 만든다(collection.json과 자신은 제외)."""
    lines = []
    skip = {name, "collection.json"}
    for root, dirs, files in os.walk(ctx.out):
        dirs.sort()
        for fn in sorted(files):
            p = os.path.join(root, fn)
            rel = ctx.rel(p)
            if rel in skip:
                continue
            sha = ctx.hashed.get(rel)
            if sha is None or rel in ("manifest.jsonl", "commands.jsonl", "errors.jsonl", "exart.log"):
                try:
                    sha = hash_file(p)[0]
                except OSError:
                    continue
            lines.append("%s  %s" % (sha, rel))
    p = ctx.path(name)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    return p, hash_file(p)[0]
