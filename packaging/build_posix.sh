#!/bin/sh
# exart 배포 폴더 빌드(macOS·Linux). 교차 빌드가 안 되므로 대상 OS·아키텍처에서 실행한다.
# onedir 로 만든다: onefile 은 실행할 때마다 대상의 임시 폴더에 런타임을 풀어 대상 디스크에 흔적을 남긴다.
# 결과: <출력>/exart-<os>-<arch>/ (실행 파일 + _internal + tools/<os>) 와 같은 이름의 .tar.gz
# 사용: sh packaging/build_posix.sh [출력폴더]   (기본 dist/)
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$HERE/dist}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
python3 -m venv "$WORK/venv"
"$WORK/venv/bin/pip" -q install "pyinstaller==6.11.1"
OS=$(uname -s | tr 'A-Z' 'a-z'); [ "$OS" = darwin ] && OS=macos
NAME="exart-$OS-$(uname -m)"
rm -rf "$OUT/$NAME" "$OUT/$NAME.tar.gz"
"$WORK/venv/bin/pyinstaller" --onedir --clean --noconfirm --name "$NAME" \
  --distpath "$OUT" --workpath "$WORK/build" --specpath "$WORK" "$HERE/exart_run.py"
mkdir -p "$OUT/$NAME/tools"
cp -R "$HERE/tools/$OS" "$OUT/$NAME/tools/"
"$OUT/$NAME/$NAME" --version
(cd "$OUT" && tar -czf "$NAME.tar.gz" "$NAME")
if command -v sha256sum >/dev/null; then (cd "$OUT" && sha256sum "$NAME.tar.gz" "$NAME/$NAME"); else (cd "$OUT" && shasum -a 256 "$NAME.tar.gz" "$NAME/$NAME"); fi
