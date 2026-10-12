# 외부 도구 배치 가이드

exart는 대부분을 OS 내장 명령으로 수집한다. 아래 외부 도구는 **있으면 쓰고 없으면 그 항목만 건너뛴다**.
라이선스 때문에 저장소에 넣지 않으므로(`.gitignore`) 각 배포처에서 받아 정해진 이름으로 둔다.
출처와 검증한 SHA-256은 [tools/windows](../tools/windows/README.md), [tools/linux](../tools/linux/README.md) README에 있다.

## 1. exart가 도구를 찾는 방법

1. 도구 폴더에서 **정해진 파일 이름**을 찾는다. 하위 폴더는 보지 않는다(파일은 폴더 바로 아래에 둔다).
2. 없으면 `PATH`에서 같은 이름을 찾는다.
3. 둘 다 없으면 그 항목을 건너뛴다. 메모리 덤프(`--memory`)만 오류로 남긴다.

이름은 표와 같아야 한다(Windows는 대소문자 구분 없음, Linux는 구분). 받은 파일 이름이 다르면(예: 버전이 붙은 이름) 표의 이름으로 바꿔 둔다.
여러 이름을 받는 도구는 아래 표의 순서대로 찾아 처음 찾은 것을 쓴다.

도구 폴더 위치:

| 실행 방식 | 도구 폴더 |
|---|---|
| 소스 실행(`python exart_run.py`) | 저장소의 `tools/<os>/` |
| 빌드한 실행 파일 | 실행 파일과 같은 폴더의 `tools/<os>/` (빌드할 때 저장소 `tools/<os>/`가 복사됨) |
| `--tools-dir <폴더>` 지정 | 지정한 폴더 (`<os>` 하위 폴더를 붙이지 않음) |

`<os>`는 `windows`, `linux`, `macos`다. 결과 폴더의 `collection.json`에 실제로 쓴 `tools_dir`가 기록된다.

## 2. Windows (`tools/windows/`)

| 파일 이름 (찾는 순서) | 모듈 · 프로필 | 쓰는 조건 | 없으면 |
|---|---|---|---|
| 64비트: `winpmem_mini_x64_rc2.exe` → `winpmem_mini_x64.exe` → `winpmem64.exe` → `go-winpmem_amd64.exe`<br>32비트: `winpmem_mini_x86.exe` → `winpmem86.exe` | memory | `--memory`, 관리자 | 오류 기록, 메모리 덤프 없음 |
| `autorunsc64.exe` (x64) / `autorunsc64a.exe` (ARM64) / `autorunsc.exe` (x86) | persistence · quick | 항상 | Autoruns CSV 없음. 예약 작업·Run 키 등 내장 수집은 그대로 |
| `icat.exe` | 잠긴 파일 복사, ntfs($MFT) · standard | 관리자 | 잠긴 파일은 `esentutl /vss`로, $MFT는 VSS 섀도 사본 + 내장 파서로 대체 |
| `fls.exe` | ntfs · standard | 관리자 | 해당 목록 없음 |
| `libewf.dll`, `zlib.dll` | icat·fls가 불러오는 DLL | — | icat·fls 실행 실패 → 위 대체 경로 |
| `ShimCacheParser.exe` | execution · quick | 항상 | ShimCache CSV 없음(SYSTEM 하이브는 따로 수집) |
| `ExecutedProgramsList.exe` | execution · standard 이상 | 항상 | 해당 CSV 없음 |
| `BrowsingHistoryView64.exe` → `BrowsingHistoryView.exe` | user_activity · quick | 항상 | 브라우저 방문 기록 CSV 없음(원본 DB는 수집) |
| `ChromeCacheView.exe`, `IECacheView.exe`, `MozillaCacheView.exe` | user_activity · full | 항상 | 캐시 목록 CSV 없음 |

함께 두면 좋은 파일(exart가 찾지는 않음):
- `Sysinternals_Autoruns_Eula.txt`: Autoruns 배포물에 들어 있는 EULA. exart는 `-accepteula`로 실행한다.
- `ExecutedProgramsList.cfg`: NirSoft 도구가 실행할 때 스스로 만드는 설정 파일. 없어도 된다.

### 주의
- **DLL은 exe와 같은 폴더에 둔다.** Windows는 exe가 있는 폴더에서 DLL을 먼저 찾는다.
- **icat·fls의 런타임**: 지금 시험에 쓴 icat/fls(32비트 빌드)는 가져오기 표에 `libewf.dll`, `zlib.dll` 외에
  `MSVCR100.dll`, `MSVCP100.dll`(Visual C++ 2010 런타임)이 있다(실행 파일의 가져오기 문자열로 확인, 실제 Windows에서 실행해 보지는 않음).
  대상 PC에 이 런타임이 없으면 icat이 시작하지 못하고 대체 경로로 넘어간다.
  The Sleuth Kit Windows 배포판 zip에 들어 있는 DLL을 **전부** `tools/windows/`에 함께 두는 것을 권한다.
- 32비트 icat도 64비트 Windows에서 원시 볼륨(`\\.\C:`)을 읽는 데 문제는 없을 것으로 보지만, 실기 검증 전이다.
- Autoruns는 아키텍처에 맞는 이름 하나만 찾는다. x64 PC에서 `autorunsc.exe`만 있으면 쓰지 않는다.
- `ShimCacheParser.exe`는 Mandiant의 Python 스크립트를 실행 파일로 만든 것이다. exart는 `-l -o <출력>`(실행 중 시스템 레지스트리)으로 부른다.

## 3. Linux (`tools/linux/`)

| 파일 이름 | 모듈 | 쓰는 조건 | 없으면 |
|---|---|---|---|
| `avml` (x86_64) / `avml-aarch64` (arm64) | memory | `--memory`, root, `--fs-root` 아님 | 오류 기록, 메모리 덤프 없음 |

- **실행 권한이 있어야 한다**: `chmod +x tools/linux/avml tools/linux/avml-aarch64`. 빌드 스크립트는 권한을 그대로 복사한다.
  외부 저장 장치가 FAT/exFAT면 권한이 사라질 수 있으니, 대상에서 `noexec`·권한을 확인한다.
- avml은 정적 링크라 배포판과 상관없다. 0.15 이후의 `avml acquire <파일>` 형식과 이전 형식을 `--help`로 판별한다.
- root와 CAP_SYS_ADMIN이 필요하다. 일반 컨테이너나 커널 lockdown 환경에서는 실패한다.

## 4. macOS (`tools/macos/`)

외부 도구가 필요 없다. 폴더는 비어 있어도 된다.

## 5. 완성된 배치 예

```
tools/
├── windows/
│   ├── README.md
│   ├── winpmem_mini_x64_rc2.exe      (또는 winpmem64.exe)
│   ├── winpmem_mini_x86.exe          (또는 winpmem86.exe)
│   ├── autorunsc.exe
│   ├── autorunsc64.exe
│   ├── autorunsc64a.exe
│   ├── Sysinternals_Autoruns_Eula.txt
│   ├── icat.exe
│   ├── fls.exe
│   ├── libewf.dll
│   ├── zlib.dll
│   ├── (TSK 배포판의 나머지 DLL)
│   ├── ShimCacheParser.exe
│   ├── ExecutedProgramsList.exe
│   ├── BrowsingHistoryView.exe
│   ├── BrowsingHistoryView64.exe
│   ├── ChromeCacheView.exe
│   ├── IECacheView.exe
│   └── MozillaCacheView.exe
├── linux/
│   ├── README.md
│   ├── avml                          (chmod +x)
│   └── avml-aarch64                  (chmod +x)
└── macos/
    └── README.md
```

빌드하면 `dist/exart-<os>-<arch>/tools/<os>/`로 복사된다. 도구를 바꾸면 다시 빌드한다([BUILD.md](BUILD.md)).

## 6. 확인

```sh
# 받은 파일의 해시를 각 README의 값과 대조
shasum -a 256 tools/windows/*.exe tools/linux/avml*          # macOS·Linux
Get-FileHash tools\windows\*.exe -Algorithm SHA256           # Windows

# Windows: 서명 확인
Get-AuthenticodeSignature tools\windows\*.exe | Format-Table Status, SignerCertificate, Path

# 어떤 도구를 쓸지 실제 수집 없이 확인(관리자/root로, 결과는 외부 저장 장치에)
exart-windows-x64.exe --profile full --memory --dry-run -y -o E:\out
./exart-linux-x86_64 --profile full --memory --dry-run -y -o /mnt/usb/out
```

dry-run 결과의 `commands.jsonl`에서 `argv[0]`이 `tools/<os>/...` 경로면 제대로 둔 것이다.
(ntfs 모듈의 $MFT icat 호출은 dry-run에서 생략되므로 이 방법으로는 보이지 않는다.)
도구 이름이 없고 내장 명령만 보이면 파일 이름이나 위치를 다시 확인한다.
