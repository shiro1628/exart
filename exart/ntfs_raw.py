# -*- coding: utf-8 -*-
"""NTFS 볼륨 장치(섀도 사본 포함)에서 $MFT 를 직접 읽는 최소 파서. 외부 도구 없이 동작한다.

부트 섹터 → MFT 레코드 0 → $DATA 런 리스트를 따라 클러스터를 그대로 복사한다.
$MFT 가 조각나 $ATTRIBUTE_LIST(상주·비상주)를 쓰면 확장 레코드의 런도 모은다.
장치 읽기는 섹터 정렬이 필요하므로 오프셋·길이를 클러스터 단위로 맞춘다.
"""
import struct

CHUNK = 4 * 1024 * 1024
BOOT_READ = 4096        # 4Kn 디스크에서도 섹터 정렬이 맞도록 4KiB 로 읽는다


class NtfsError(Exception):
    pass


def _read(dev, off, size):
    dev.seek(off)
    buf = bytearray()
    while len(buf) < size:
        b = dev.read(size - len(buf))
        if not b:
            raise NtfsError("읽기가 짧음: offset %d, %d/%d 바이트" % (off, len(buf), size))
        buf += b
    return buf


def parse_boot(bs):
    """(섹터 크기, 클러스터 크기, $MFT 시작 LCN, MFT 레코드 크기)."""
    if bytes(bs[3:11]) != b"NTFS    ":
        raise NtfsError("NTFS 부트 섹터가 아님")
    bps = struct.unpack_from("<H", bs, 0x0B)[0]
    spc = bs[0x0D]
    if spc > 0x80:
        spc = 1 << (256 - spc)
    cluster = bps * spc
    mft_lcn = struct.unpack_from("<Q", bs, 0x30)[0]
    cpr = struct.unpack_from("<b", bs, 0x40)[0]
    rec = cluster * cpr if cpr > 0 else 1 << (-cpr)
    if bps not in (512, 1024, 2048, 4096) or cluster & (cluster - 1) or not 0 < cluster <= 2 * 1024 * 1024:
        raise NtfsError("부트 섹터 값이 이상함: 섹터 %d, 클러스터 %d" % (bps, cluster))
    if rec & (rec - 1) or not 256 <= rec <= 65536:
        raise NtfsError("MFT 레코드 크기가 이상함: %d" % rec)
    return bps, cluster, mft_lcn, rec


def apply_fixup(rec):
    """MFT 레코드의 업데이트 시퀀스(fixup)를 되돌린다."""
    rec = bytearray(rec)
    if bytes(rec[0:4]) != b"FILE":
        raise NtfsError("MFT 레코드 서명(FILE)이 없음")
    usa_off, usa_cnt = struct.unpack_from("<HH", rec, 4)
    if usa_cnt < 2 or usa_off + usa_cnt * 2 > len(rec) or len(rec) % (usa_cnt - 1):
        raise NtfsError("fixup 배열이 이상함")
    stride = len(rec) // (usa_cnt - 1)
    usn = rec[usa_off:usa_off + 2]
    for i in range(1, usa_cnt):
        end = i * stride
        if rec[end - 2:end] != usn:
            raise NtfsError("fixup 불일치(레코드가 깨졌거나 쓰는 중)")
        rec[end - 2:end] = rec[usa_off + i * 2:usa_off + i * 2 + 2]
    return rec


def attributes(rec):
    off = struct.unpack_from("<H", rec, 0x14)[0]
    while off + 8 <= len(rec):
        atype, alen = struct.unpack_from("<II", rec, off)
        if atype == 0xFFFFFFFF or alen < 16 or off + alen > len(rec):
            break
        yield atype, rec[off:off + alen]
        off += alen


def decode_runs(attr):
    """비상주 속성의 런 리스트 → [(VCN, LCN, 클러스터 수)]. 희소 런은 LCN 이 None."""
    vcn = struct.unpack_from("<Q", attr, 0x10)[0]
    pos = struct.unpack_from("<H", attr, 0x20)[0]
    lcn, runs = 0, []
    while pos < len(attr) and attr[pos]:
        ln, ofs = attr[pos] & 0x0F, attr[pos] >> 4
        pos += 1
        if ln == 0 or pos + ln + ofs > len(attr):
            raise NtfsError("런 리스트가 깨짐")
        length = int.from_bytes(bytes(attr[pos:pos + ln]), "little")
        pos += ln
        if ofs:
            lcn += int.from_bytes(bytes(attr[pos:pos + ofs]), "little", signed=True)
            pos += ofs
            runs.append((vcn, lcn, length))
        else:
            runs.append((vcn, None, length))
        vcn += length
    return runs


def _unnamed_data(rec):
    return [a for t, a in attributes(rec) if t == 0x80 and a[9] == 0]


def _attr_value(dev, cluster, attr):
    """속성 값. 상주면 레코드 안에서, 비상주면 볼륨의 클러스터에서 읽는다."""
    if not attr[8]:
        vlen, voff = struct.unpack_from("<IH", attr, 0x10)
        return attr[voff:voff + vlen]
    size = struct.unpack_from("<Q", attr, 0x30)[0]
    buf = bytearray()
    for _, lcn, length in decode_runs(attr):
        if lcn is None:
            buf += bytes(length * cluster)
        else:
            buf += _read(dev, lcn * cluster, length * cluster)
        if len(buf) >= size:
            break
    return buf[:size]


def _data_extension_refs(val):
    """$ATTRIBUTE_LIST 값에서 이름 없는 $DATA 조각을 담은 레코드 번호들."""
    p, refs = 0, set()
    while p + 0x1A <= len(val):
        etype, elen, enl = struct.unpack_from("<IHB", val, p)
        if elen == 0:
            break
        ref = struct.unpack_from("<Q", val, p + 0x10)[0] & 0xFFFFFFFFFFFF
        if etype == 0x80 and enl == 0 and ref:
            refs.add(ref)
        p += elen
    return refs


class _Mft(object):
    def __init__(self, dev, cluster, rec_size):
        self.dev, self.cluster, self.rec_size = dev, cluster, rec_size
        self.runs, self.size = {}, None

    def add(self, attr):
        if not attr[8]:
            raise NtfsError("$MFT 의 $DATA 가 상주 속성")
        if struct.unpack_from("<Q", attr, 0x10)[0] == 0:
            self.size = struct.unpack_from("<Q", attr, 0x30)[0]
        for vcn, lcn, length in decode_runs(attr):
            if lcn is None:
                raise NtfsError("$MFT 에 희소 런이 있음")
            self.runs[vcn] = (lcn, length)

    def ordered(self):
        out, nxt = [], 0
        for vcn in sorted(self.runs):
            if vcn != nxt:
                raise NtfsError("$MFT 런이 이어지지 않음(VCN %d 기대, %d 발견)" % (nxt, vcn))
            lcn, length = self.runs[vcn]
            out.append((vcn, lcn, length))
            nxt = vcn + length
        return out

    def read_clusters(self, vcn, count):
        buf = bytearray()
        for rv, lcn, length in self.ordered():
            while count and rv <= vcn < rv + length:
                n = min(count, rv + length - vcn)
                buf += _read(self.dev, (lcn + vcn - rv) * self.cluster, n * self.cluster)
                vcn += n
                count -= n
        if count:
            raise NtfsError("$MFT 범위 밖 VCN %d" % vcn)
        return buf

    def record(self, num):
        off = num * self.rec_size
        first = off // self.cluster
        last = (off + self.rec_size - 1) // self.cluster
        data = self.read_clusters(first, last - first + 1)
        start = off - first * self.cluster
        return apply_fixup(data[start:start + self.rec_size])


def read_mft(dev, out):
    """dev(바이너리 파일 객체, 볼륨 장치나 이미지)에서 $MFT 를 out 에 쓴다. 정보 dict 를 돌려준다."""
    bps, cluster, mft_lcn, rec_size = parse_boot(_read(dev, 0, BOOT_READ))
    first = _read(dev, mft_lcn * cluster, max(rec_size, cluster))[:rec_size]
    rec0 = apply_fixup(first)
    mft = _Mft(dev, cluster, rec_size)
    for a in _unnamed_data(rec0):
        mft.add(a)
    if not mft.runs:
        raise NtfsError("레코드 0 에 $DATA 가 없음")
    refs = set()
    for t, a in attributes(rec0):
        if t == 0x20:
            refs |= _data_extension_refs(_attr_value(dev, cluster, a))
    # 확장 레코드가 아직 모르는 런에 있을 수 있으므로, 읽을 수 있는 것부터 반복해서 처리한다
    pending, extensions = sorted(refs), 0
    while pending:
        left = []
        for ref in pending:
            try:
                rec = mft.record(ref)
            except NtfsError:
                left.append(ref)
                continue
            for d in _unnamed_data(rec):
                mft.add(d)
            extensions += 1
        if len(left) == len(pending):
            raise NtfsError("$MFT 확장 레코드를 읽지 못함: %s" % left[:5])
        pending = left
    if mft.size is None:
        raise NtfsError("$MFT 크기를 찾지 못함")
    runs = mft.ordered()
    if mft.size > (runs[-1][0] + runs[-1][2]) * cluster:
        raise NtfsError("$MFT 크기가 런 범위보다 큼")
    remaining = mft.size
    per = max(1, CHUNK // cluster)
    for vcn, lcn, length in runs:
        i = 0
        while i < length and remaining > 0:
            n = min(per, length - i)
            data = _read(dev, (lcn + i) * cluster, n * cluster)
            take = min(len(data), remaining)
            out.write(bytes(data[:take]))
            remaining -= take
            i += n
    return {"size": mft.size, "cluster_size": cluster, "record_size": rec_size, "sector_size": bps,
            "mft_lcn": mft_lcn, "runs": len(runs), "extension_records": extensions}
