#!/bin/sh
# Windows 배포 폴더를 Docker + Wine(tobix/pywine:3.8)으로 빌드한다. Windows 없이 macOS·Linux에서 쓴다.
# Python 3.8 기반이라 Windows 7 SP1 이상에서 돈다. onedir 인 이유는 build_posix.sh 참고.
# 결과: dist/exart-windows-x64/ (exe + _internal + tools/windows) 와 .zip
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
NAME=exart-windows-x64
mkdir -p "$HERE/dist"
rm -rf "$HERE/dist/$NAME" "$HERE/dist/$NAME.zip"
docker run --rm --platform linux/amd64 -e PYTHONDONTWRITEBYTECODE=1 -e WINEDEBUG=-all \
  -v "$HERE:/src:ro" -v "$HERE/dist:/dist" tobix/pywine:3.8 sh -c '
    wine python -m pip -q install pyinstaller==6.11.1 &&
    cd /tmp && wine pyinstaller --onedir --clean --noconfirm --name '"$NAME"' \
      --distpath Z:\\dist --workpath Z:\\tmp\\build --specpath Z:\\tmp Z:\\src\\exart_run.py >/tmp/build.log 2>&1 ||
      { tail -30 /tmp/build.log; exit 1; }
    wine Z:\\dist\\'"$NAME"'\\'"$NAME"'.exe --version'
mkdir -p "$HERE/dist/$NAME/tools"
cp -R "$HERE/tools/windows" "$HERE/dist/$NAME/tools/"
(cd "$HERE/dist" && rm -f "$NAME.zip" && zip -qr "$NAME.zip" "$NAME" && \
  (shasum -a 256 "$NAME.zip" "$NAME/$NAME.exe" 2>/dev/null || sha256sum "$NAME.zip" "$NAME/$NAME.exe"))
