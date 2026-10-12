# -*- coding: utf-8 -*-
"""코어·파서 단위 테스트. 실행: python3 -m unittest discover -s tests"""
import json
import os
import shutil
import socket
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from exart import core, linux, ntfs_raw  # noqa: E402
from exart import cli  # noqa: E402,F401  (모듈 등록 확인용)


class TimeAndSize(unittest.TestCase):
    def test_parse_time_kst_default(self):
        self.assertEqual(core.iso(core.parse_time("2026-10-01")), "2026-09-30T15:00:00Z")
        self.assertEqual(core.iso(core.parse_time("2026-10-01 09:30")), "2026-10-01T00:30:00Z")

    def test_parse_time_utc_suffix(self):
        self.assertEqual(core.iso(core.parse_time("2026-10-01T00:00Z")), "2026-10-01T00:00:00Z")

    def test_parse_time_bad(self):
        with self.assertRaises(ValueError):
            core.parse_time("10/01/2026")

    def test_parse_size(self):
        self.assertEqual(core.parse_size("20M"), 20 << 20)
        self.assertEqual(core.parse_size("1.5G"), int(1.5 * (1 << 30)))
        self.assertEqual(core.parse_size("0"), 0)


class Mangle(unittest.TestCase):
    def test_windows_path(self):
        self.assertEqual(core.mangle(r"C:\Users\a b\NTUSER.DAT"), "C/Users/a b/NTUSER.DAT")
        self.assertEqual(core.mangle("\\\\?\\c:\\x\\y"), "C/x/y")

    def test_posix_path(self):
        self.assertEqual(core.mangle("/etc/passwd"), "etc/passwd")

    def test_unsafe_chars_and_traversal(self):
        self.assertEqual(core.mangle("/tmp/a:b*c?/../x"), "tmp/a_b_c_/x")

    def test_sniff(self):
        self.assertEqual(core.sniff(b"MZ\x90\x00"), "pe")
        self.assertEqual(core.sniff(b"\x7fELF\x02"), "elf")
        self.assertEqual(core.sniff(b"\xcf\xfa\xed\xfe"), "macho")
        self.assertEqual(core.sniff(b"#!/bin/sh"), "script")
        self.assertIsNone(core.sniff(b"hello"))


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = os.path.join(self.tmp, "src")
        os.makedirs(os.path.join(self.src, "sub"))
        with open(os.path.join(self.src, "a.txt"), "wb") as f:
            f.write(b"hello")
        with open(os.path.join(self.src, "sub", "evil"), "wb") as f:
            f.write(b"\x7fELF" + b"\0" * 100)
        with open(os.path.join(self.src, "big.bin"), "wb") as f:
            f.write(b"x" * 2048)
        os.utime(os.path.join(self.src, "a.txt"), (1000000000, 1000000000))
        self.out = os.path.join(self.tmp, "out")
        self.ctx = core.Context(self.out, "linux", max_size=1024)
        self.ctx.module = "test"

    def tearDown(self):
        self.ctx.close()
        shutil.rmtree(self.tmp)

    def manifest(self):
        self.ctx._manifest.flush()
        with open(os.path.join(self.out, "manifest.jsonl"), encoding="utf-8") as f:
            return [json.loads(l) for l in f]

    def test_copy_preserves_mtime_and_hashes(self):
        e = self.ctx.copy(os.path.join(self.src, "a.txt"), "t")
        self.assertEqual(e["status"], "ok")
        self.assertEqual(e["sha256"], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        self.assertEqual(e["mtime"], "2001-09-09T01:46:40Z")
        dest = os.path.join(self.out, *e["dest"].split("/"))
        self.assertEqual(int(os.stat(dest).st_mtime), 1000000000)

    def test_copy_too_large_and_duplicate(self):
        self.assertEqual(self.ctx.copy(os.path.join(self.src, "big.bin"), "t")["reason"], "too_large")
        self.assertEqual(self.ctx.copy(os.path.join(self.src, "big.bin"), "t", max_size=0)["status"], "ok")
        self.assertEqual(self.ctx.copy(os.path.join(self.src, "big.bin"), "t", max_size=0)["reason"], "duplicate")

    def test_copy_missing_records_error(self):
        e = self.ctx.copy(os.path.join(self.src, "nope"), "t")
        self.assertEqual(e["status"], "error")
        self.assertEqual(self.ctx.stats["errors"], 1)

    def test_symlink_not_followed(self):
        link = os.path.join(self.src, "link")
        os.symlink("/etc/passwd", link)
        e = self.ctx.copy(link, "t")
        self.assertEqual(e["reason"], "symlink")
        self.assertEqual(e["link_target"], "/etc/passwd")

    def test_file_listing_collects_executables(self):
        n = self.ctx.file_listing("l.csv", [self.src], hash_files=True,
                                  collect=lambda p, st, kind: "exec" if kind == "elf" else None)
        self.assertEqual(n, 4)       # a.txt, big.bin, sub, sub/evil
        collected = [m for m in self.manifest() if m.get("category") == "exec"]
        self.assertEqual(len(collected), 1)
        self.assertEqual(self.ctx.stats["executables"], 1)

    def test_dest_collision_not_overwritten(self):
        a = os.path.join(self.src, "x:y")
        b = os.path.join(self.src, "x_y")
        for path, data in ((a, b"first"), (b, b"second")):
            with open(path, "wb") as f:
                f.write(data)
        e1 = self.ctx.copy(a, "t")
        e2 = self.ctx.copy(b, "t")
        self.assertNotEqual(e1["dest"], e2["dest"])
        self.assertTrue(e2["dest"].endswith("x_y~2"))
        with open(os.path.join(self.out, *e1["dest"].split("/")), "rb") as f:
            self.assertEqual(f.read(), b"first")

    def test_cloud_placeholder(self):
        class St(object):
            st_file_attributes = 0x00400000
        self.assertTrue(core.is_cloud_placeholder(St()))
        self.assertFalse(core.is_cloud_placeholder(os.stat(self.src)))

    def test_walk_nested_roots_not_duplicated(self):
        paths = [p for p, _ in self.ctx.walk([self.src, os.path.join(self.src, "sub")])]
        self.assertEqual(len(paths), len(set(paths)))
        paths = [p for p, _ in self.ctx.walk([self.src, os.path.join(self.src, "sub")], xdev=True)]
        self.assertEqual(len(paths), len(set(paths)))

    def test_walk_skips_output_dir(self):
        ctx2 = core.Context(os.path.join(self.src, "out2"), "linux")
        try:
            paths = [p for p, _ in ctx2.walk([self.src])]
            self.assertFalse(any("out2" in p for p in paths))
        finally:
            ctx2.close()

    def test_run_and_hash_list(self):
        rc = self.ctx.run([sys.executable, "-c", "print('hi')"], "cmd/out.txt")
        self.assertEqual(rc, 0)
        self.assertIsNone(self.ctx.run(["definitely-not-a-command-xyz"], "cmd/none.txt"))
        self.ctx.close()
        path, sha = core.write_hash_list(self.ctx)
        with open(path) as f:
            body = f.read()
        self.assertIn("cmd/out.txt", body)
        self.assertNotIn("collection.json", body)
        self.assertEqual(len(sha), 64)

    def test_in_window(self):
        self.ctx.since = core.parse_time("2001-09-01")
        self.ctx.until = core.parse_time("2001-09-30")
        st = os.stat(os.path.join(self.src, "a.txt"))
        # ctime 은 방금(테스트 생성 시각)이라 창 밖, mtime 은 2001-09-09 라 창 안
        self.assertTrue(self.ctx.in_window(st))


class VerifyTests(unittest.TestCase):
    def test_verify_detects_tampering(self):
        tmp = tempfile.mkdtemp()
        try:
            out = os.path.join(tmp, "o")
            rc = cli.main(["-o", out, "--modules", "environment", "-y", "--allow-same-volume"]) \
                if sys.platform.startswith("linux") else None
            folder = None
            if rc is None:      # linux 외 OS: 코어만으로 결과 폴더를 흉내 낸다
                folder = os.path.join(out, "x")
                ctx = core.Context(folder, "linux")
                ctx.write_text("a.txt", "hello")
                ctx.close()
                _, sha = core.write_hash_list(ctx)
                with open(os.path.join(folder, "collection.json"), "w") as f:
                    json.dump({"integrity": {"hash_list_sha256": sha}, "modules": [], "summary": "t",
                               "stats": {}}, f)
            else:
                folder = os.path.join(out, os.listdir(out)[0])
            from exart.verify import verify
            lines = []
            self.assertEqual(verify(folder, out=lines.append), 0)
            with open(os.path.join(folder, "manifest.jsonl"), "a") as f:
                f.write("tampered\n")
            self.assertEqual(verify(folder, out=lines.append), 1)
        finally:
            shutil.rmtree(tmp)


class Registry(unittest.TestCase):
    def test_each_os_has_modules_in_order(self):
        for os_name in ("windows", "macos", "linux"):
            mods = core.modules_for(os_name, "full")
            self.assertTrue(mods)
            self.assertEqual([m.order for m in mods], sorted(m.order for m in mods))

    def test_profile_subset(self):
        for os_name in ("windows", "macos", "linux"):
            q = set(m.name for m in core.modules_for(os_name, "quick"))
            s = set(m.name for m in core.modules_for(os_name, "standard"))
            f = set(m.name for m in core.modules_for(os_name, "full"))
            self.assertTrue(q <= s <= f)

    def test_unknown_module(self):
        with self.assertRaises(ValueError):
            core.modules_for("linux", only=["nope"])


class LinuxParsers(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(linux._addr("0100007F:1F90", False), ("127.0.0.1", 8080))

    def test_ipv6(self):
        raw = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        words = struct.unpack(">4I", raw)
        hexaddr = "".join("%08X" % struct.unpack("<I", struct.pack(">I", w))[0] for w in words)
        self.assertEqual(linux._addr(hexaddr + ":0050", True), ("2001:db8::1", 80))

    def test_shadow_redaction(self):
        text = "root:$6$salt$hash:19000:0:99999:7:::\nbin:*:19000::::::\nbob:!$y$j9T$abc:19000::::::\n"
        out = linux._redacted_shadow(text)
        self.assertNotIn("hash", out)
        self.assertNotIn("abc", out)
        self.assertIn("root:<redacted:6>:19000", out)
        self.assertIn("bin:*:", out)
        self.assertIn("bob:!<redacted:y>:", out)


def _ntfs_image():
    """클러스터 4096, MFT 레코드 1024, $MFT 가 LCN 2 와 5 의 두 조각(크기 6000)인 최소 이미지."""
    img = bytearray(4096 * 8)
    for c in range(8):
        img[c * 4096:(c + 1) * 4096] = bytes([0x40 + c]) * 4096
    boot = bytearray(512)
    boot[3:11] = b"NTFS    "
    struct.pack_into("<HB", boot, 0x0B, 512, 8)
    struct.pack_into("<Q", boot, 0x30, 2)
    struct.pack_into("<b", boot, 0x40, -10)
    img[0:512] = boot
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    struct.pack_into("<HHH", rec, 4, 0x30, 3, 0)
    struct.pack_into("<H", rec, 0x14, 0x38)
    attr = bytearray(0x48)
    struct.pack_into("<IIBB", attr, 0, 0x80, 0x48, 1, 0)
    struct.pack_into("<QQH", attr, 0x10, 0, 1, 0x40)
    struct.pack_into("<QQQ", attr, 0x28, 8192, 6000, 6000)
    attr[0x40:0x47] = b"\x11\x01\x02\x11\x01\x03\x00"
    rec[0x38:0x38 + 0x48] = attr
    struct.pack_into("<I", rec, 0x38 + 0x48, 0xFFFFFFFF)
    rec[0x30:0x32] = b"\x07\x00"                       # USN
    for i in (1, 2):                                     # 섹터 끝 2바이트를 fixup 배열로 옮긴다
        rec[0x30 + i * 2:0x32 + i * 2] = rec[i * 512 - 2:i * 512]
        rec[i * 512 - 2:i * 512] = b"\x07\x00"
    img[8192:8192 + 1024] = rec
    return img


class NtfsRaw(unittest.TestCase):
    def test_read_fragmented_mft(self):
        import io
        img = _ntfs_image()
        out = io.BytesIO()
        info = ntfs_raw.read_mft(io.BytesIO(bytes(img)), out)
        self.assertEqual(info["runs"], 2)
        self.assertEqual(out.getvalue(), bytes(img[8192:12288] + img[20480:20480 + 6000 - 4096]))

    def test_not_ntfs(self):
        import io
        with self.assertRaises(ntfs_raw.NtfsError):
            ntfs_raw.read_mft(io.BytesIO(bytes(8192)), io.BytesIO())

    def test_fixup_mismatch(self):
        import io
        img = _ntfs_image()
        img[8192 + 510] ^= 0xFF
        with self.assertRaises(ntfs_raw.NtfsError):
            ntfs_raw.read_mft(io.BytesIO(bytes(img)), io.BytesIO())


if __name__ == "__main__":
    unittest.main()
