# -*- coding: utf-8 -*-
"""수집 결과 폴더 검증: SHA256SUMS 대조와 모듈별 결과 요약.

증거를 넘겨받았을 때 무결성 확인용이며, 새 OS에서 처음 돌린 결과를 점검할 때도 쓴다.
"""
import collections
import json
import os

from . import core


def verify(folder, out=print):
    """문제가 없으면 0, 해시 불일치·누락이 있으면 1, 폴더가 이상하면 2."""
    folder = os.path.abspath(folder)
    sums = os.path.join(folder, "SHA256SUMS")
    meta_path = os.path.join(folder, "collection.json")
    if not os.path.isfile(sums) or not os.path.isfile(meta_path):
        out("exart 결과 폴더가 아님(SHA256SUMS·collection.json 없음): %s" % folder)
        return 2
    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)
    rc = 0

    sums_sha = core.hash_file(sums)[0]
    recorded = meta.get("integrity", {}).get("hash_list_sha256")
    out("SHA256SUMS sha256 : %s %s" % (sums_sha, "(collection.json 과 일치)" if sums_sha == recorded
                                       else "(collection.json 값 %s 과 다름!)" % recorded))
    if sums_sha != recorded:
        rc = 1

    listed, bad, missing = set(), [], []
    with open(sums, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            sha, rel = line.split("  ", 1)
            listed.add(rel)
            p = os.path.join(folder, *rel.split("/"))
            if not os.path.isfile(p):
                missing.append(rel)
                continue
            if core.hash_file(p)[0] != sha:
                bad.append(rel)
    extra = []
    for root, _, files in os.walk(folder):
        for fn in files:
            rel = os.path.relpath(os.path.join(root, fn), folder).replace(os.sep, "/")
            if rel not in listed and rel not in ("SHA256SUMS", "collection.json"):
                extra.append(rel)
    out("파일 %d개 대조: 불일치 %d, 누락 %d, 목록에 없는 파일 %d" % (len(listed), len(bad), len(missing), len(extra)))
    for label, items in (("불일치", bad), ("누락", missing), ("추가됨", extra)):
        for rel in items[:20]:
            out("  [%s] %s" % (label, rel))
    if bad or missing or extra:
        rc = 1

    out("")
    out("%s" % meta.get("summary"))
    host = meta.get("host", {})
    out("호스트 %s / %s / 실행자 %s(관리자 %s) / 프로필 %s" % (
        host.get("hostname"), host.get("distribution") or host.get("platform"), meta.get("operator", {}).get("user"),
        meta.get("operator", {}).get("is_admin"), meta.get("profile")))
    errs = collections.defaultdict(list)
    err_path = os.path.join(folder, "errors.jsonl")
    if os.path.isfile(err_path):
        with open(err_path, encoding="utf-8") as f:
            for line in f:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                errs[e.get("module")].append(e.get("message"))
    out("\n%-16s %-10s %8s %6s" % ("모듈", "상태", "시간(s)", "오류"))
    for m in meta.get("modules", []):
        out("%-16s %-10s %8s %6d" % (m["name"], m["status"], m.get("duration_s"), len(errs.get(m["name"], []))))
        for msg in errs.get(m["name"], [])[:5]:
            out("    - %s" % msg[:200])
        if len(errs.get(m["name"], [])) > 5:
            out("    ... 외 %d건" % (len(errs[m["name"]]) - 5))
    if meta.get("contains_executables"):
        out("\n[주의] 실행 파일 %d개가 들어 있습니다. 격리 환경에서만 분석하세요." % meta["stats"].get("executables", 0))
    return rc
