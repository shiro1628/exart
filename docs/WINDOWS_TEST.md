# Windows 실기 점검 절차

Windows 수집기는 지금까지 **Wine에서만** 돌려 봤다. Python 코드 경로와 PowerShell 문법은
확인했지만 reg save, wevtutil, esentutl /vss, PowerShell 수집, icat 원시 읽기는 실제 Windows에서만 확인할 수 있다.
테스트 전용 PC나 가상 머신에서 아래 순서로 한 번 점검한다.

## 준비
1. USB(또는 두 번째 디스크) `E:\` 에 다음을 복사한다.
   - `dist\exart-windows-x64\` 폴더 전체(실행 파일, `_internal`, `tools\windows`)
2. 복사한 exe 해시를 빌드할 때 기록한 해시와 대조한다: `Get-FileHash E:\exart-windows-x64\exart-windows-x64.exe`
3. 번들 도구 서명 확인:
   `Get-ChildItem E:\exart-windows-x64\tools\windows\*.exe | Get-AuthenticodeSignature | ft Status,Path -Auto`

## 실행(관리자 PowerShell)
```powershell
E:\exart-windows-x64\exart-windows-x64.exe -o E:\test --case-id WINTEST --profile standard --since 2026-10-01
E:\exart-windows-x64\exart-windows-x64.exe --verify (Get-ChildItem E:\test -Directory | Select -Last 1).FullName
```
`--memory`, `--profile full`은 시간이 오래 걸리니 standard가 통과한 뒤 따로 시험한다.

## 확인할 것
| 항목 | 기대 | 결과 |
|---|---|---|
| `--verify` 해시 대조 | 불일치·누락 0 | |
| 모든 모듈 상태 | `ok`(failed 없음) | |
| `files\registry\HKLM\` | SAM, SECURITY, SYSTEM, SOFTWARE (reg save) | |
| `files\registry\users\<SID>\` | 로그온 사용자 NTUSER.DAT·UsrClass.dat | |
| `files\eventlogs\` | Security.evtx 등, Event Viewer로 열림 | |
| `eventlogs_filtered\logon__Security.txt` | 최근 4624 이벤트가 텍스트로 보임 | |
| `volatile\processes.csv`, `tcp_connections.csv` | 한글 경로·사용자명이 깨지지 않음 | |
| `volatile\image_signatures.csv` | Status 열이 Valid/NotSigned 등으로 채워짐 | |
| `files\execution\amcache\` | Amcache.hve (esentutl-vss 또는 forecopy로 복사) | |
| `files\ntfs\C\$MFT` | 수백 MB 이상, `ntfs\C_usnjrnl.csv` 생성 | |
| `persistence\autoruns.csv` | autorunsc 결과(UTF-16) | |
| 콘솔 출력 | 한글이 깨지거나 멈추지 않음(일본어 Windows면 특히) | |
| 소요 시간 | 기록 | |

`errors.jsonl`의 내용과 위 결과를 기록하고, 실패한 항목은 `logs\`, `*.stderr`, `scripts\*.ps1`을 함께 본다.

## 주의
- EDR이 reg save(SAM), esentutl /vss, 메모리 덤프를 탐지할 수 있다. 테스트 전에 보안 운영 쪽에 알린다.
- `esentutl /vss`는 임시 볼륨 섀도 사본을 만들고 지운다.
- 결과 폴더에는 SAM 하이브(로컬 계정 해시)가 들어 있으니 테스트가 끝나면 지운다.
