# 배포 폴더 빌드

대상에 파이썬(3.6 이상)이 있으면 빌드 없이 `python3 exart_run.py`로 소스를 직접 실행한다.
파이썬이 없는 대상(Windows, 최소 설치 Linux 등)에 가져갈 실행 파일이 필요할 때만 빌드한다.

`dist/`는 Git에서 제외되므로 새로 클론했을 때, `exart/` 코드를 고쳤을 때, `tools/<os>/`의 외부 도구를 바꿨을 때 다시 빌드한다.

## 결과물

PyInstaller onedir 형식이다. onefile은 실행할 때마다 대상의 임시 폴더에 런타임을 풀어 대상 디스크에 흔적을 남기므로 쓰지 않는다.

```
dist/
  exart-<os>-<arch>/
    exart-<os>-<arch>[.exe]   실행 파일
    _internal/                런타임
    tools/<os>/               외부 도구(빌드할 때 tools/<os>/에서 복사)
  exart-<os>-<arch>.tar.gz    (Windows는 .zip)
```

| 대상 | 결과 이름 | 빌드 환경 |
|---|---|---|
| Windows 7 SP1 이상 x64 | `exart-windows-x64` | Docker + Wine(`tobix/pywine:3.8`), 또는 Windows |
| Apple Silicon Mac | `exart-macos-arm64` | Apple Silicon Mac |
| Linux x86_64 (glibc 2.31 이상) | `exart-linux-x86_64` | Docker `python:3.8-slim-bullseye` (`linux/amd64`) |
| Linux aarch64 (glibc 2.31 이상) | `exart-linux-aarch64` | Docker `python:3.8-slim-bullseye` (`linux/arm64`) |

교차 빌드는 안 된다. 각 OS·아키텍처 환경(또는 해당 플랫폼의 Docker 컨테이너)에서 빌드한다.
Linux를 glibc 2.31(Debian 11) 이미지에서 빌드하는 이유는 그보다 새로운 시스템에서만 돌기 때문이다(glibc 하위 호환).

## 준비

- 인터넷 연결: 빌드할 때마다 PyInstaller 6.11.1을 받는다(임시 venv 또는 컨테이너 안에 설치, 끝나면 지움).
- Docker: Windows·Linux 빌드에 필요하다. Apple Silicon에서 `linux/amd64` 이미지는 에뮬레이션으로 돌아 느리다.
- 외부 도구: `tools/<os>/`에 넣고 각 README의 SHA-256과 대조해 둔다. 없어도 빌드는 되고, 해당 기능만 건너뛴다.

## 명령

모두 저장소 루트에서 실행한다. 각 스크립트는 같은 이름의 기존 결과를 지우고 새로 만든다.

```sh
# Windows x64 (macOS·Linux에서 Docker + Wine)
sh packaging/build_windows_docker.sh

# macOS arm64 (Mac에서 직접)
sh packaging/build_posix.sh

# Linux x86_64
docker run --rm --platform linux/amd64 -v $PWD:/src:ro -v $PWD/dist:/dist python:3.8-slim-bullseye \
  sh -c 'apt-get update -qq && apt-get install -y -qq binutils && sh /src/packaging/build_posix.sh /dist'

# Linux aarch64
docker run --rm --platform linux/arm64 -v $PWD:/src:ro -v $PWD/dist:/dist python:3.8-slim-bullseye \
  sh -c 'apt-get update -qq && apt-get install -y -qq binutils && sh /src/packaging/build_posix.sh /dist'
```

Windows에서 직접 빌드할 때(Python 3.8 권장 — 3.9 이상으로 빌드하면 Windows 7에서 돌지 않는다):

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
```

`build_posix.sh`는 인자로 출력 폴더를 받는다(기본 `dist/`).

## 빌드 뒤 확인

1. 스크립트가 마지막에 실행 파일의 `--version`을 출력한다. `exart 2.x.x`가 나오면 실행 파일이 정상이다.
2. 이어서 압축 파일과 실행 파일의 SHA-256을 출력한다. **이 값을 기록해 두고 현장에서 대조한다.**
3. 모듈 목록과 계획만 확인하려면:
   ```sh
   dist/exart-macos-arm64/exart-macos-arm64 --list-modules
   ```
4. Windows 빌드는 Wine에서만 확인된 상태다. 실제 Windows 점검은 `docs/WINDOWS_TEST.md`를 따른다.

## 배포

`exart-<os>-<arch>/` 폴더를 통째로(실행 파일, `_internal/`, `tools/`) 외부 저장 장치에 복사한다.
실행 파일만 옮기면 돌지 않는다. 압축 파일을 옮겼다면 대상이 아닌 분석 쪽에서 풀어 USB에 둔다(대상 디스크에 풀지 않는다).

## 문제 해결

| 증상 | 원인·조치 |
|---|---|
| Linux에서 `GLIBC_2.xx not found` | 대상 glibc가 2.31보다 오래됨(RHEL 7·8 등). 소스 실행(`python3 exart_run.py`, RHEL 8은 `/usr/libexec/platform-python`) |
| Alpine에서 실행 파일이 안 돎 | musl 기반이라 glibc 빌드가 맞지 않음. 소스 실행 |
| Intel Mac | arm64 빌드만 있음. Intel Mac에서 `build_posix.sh`로 빌드하거나 소스 실행 |
| Windows 빌드가 실패하고 로그 끝 30줄만 나옴 | Wine 안 PyInstaller 오류. Docker 이미지 재다운로드(`docker pull tobix/pywine:3.8`) 후 재시도 |
| `pip install` 실패 | 인터넷 연결·프록시 확인 |
