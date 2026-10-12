# Windows 외부 도구

exart는 대부분을 OS 내장 명령(wevtutil, reg, esentutl, fsutil, PowerShell)으로 수집한다.
아래 도구는 **있으면 쓰고 없으면 건너뛴다**. 라이선스 때문에 저장소에는 넣지 않으며(`.gitignore`),
각자 공식 배포처에서 받아 이 폴더에 둔다. 받은 뒤 아래 SHA-256과 대조하고, Windows에서
`Get-AuthenticodeSignature`로 서명을 확인한다.

| 파일 | 쓰는 모듈 | 출처 |
|---|---|---|
| `winpmem_mini_x64_rc2.exe`, `winpmem_mini_x86.exe` | memory | [Velocidex WinPmem v4.0.rc1](https://github.com/Velocidex/WinPmem/releases/tag/v4.0.rc1) |
| `icat.exe`, `fls.exe` (+`libewf.dll`, `zlib.dll`) | ntfs, 잠긴 파일 | [The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/download.php) Windows 배포판 ([GitHub releases](https://github.com/sleuthkit/sleuthkit/releases)) |
| `ShimCacheParser.exe` | execution | [Mandiant ShimCacheParser](https://github.com/mandiant/ShimCacheParser)(Python)를 PyInstaller 등으로 실행 파일로 만든 것 |
| `BrowsingHistoryView(64).exe`, `ChromeCacheView.exe`, `IECacheView.exe`, `MozillaCacheView.exe`, `ExecutedProgramsList.exe` | browsers, execution | NirSoft: [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html), [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html), [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html), [ExecutedProgramsList](https://www.nirsoft.net/utils/executed_programs_list.html) |
| `autorunsc64.exe`, `autorunsc.exe`, `autorunsc64a.exe` | persistence | [Sysinternals Autoruns](https://learn.microsoft.com/sysinternals/downloads/autoruns) ([Autoruns.zip](https://download.sysinternals.com/files/Autoruns.zip)). 재배포 금지 EULA |

이름이 `winpmem64.exe`/`winpmem86.exe`인 파일도 찾는다(mini 빌드를 이름만 바꾼 경우).

서명 체인(2026-10 확인): autorunsc는 Microsoft Code Signing PCA 2024 → Microsoft Root CA 2011, 타임스탬프는 Root CA 2010.
winpmem_mini는 Velocidex → Sectigo RSA Code Signing CA → USERTrust RSA이며, 서명 인증서는 만료됐지만 서명 시점(2020-10-13)에는 유효했고 타임스탬프가 붙어 있다.

검증에 쓴 SHA-256:
```
a4d516b6fcaf3b5b1d4ee709ce86f8eabf1d8028b3a83101479b7568b933d21b  winpmem_mini_x64_rc2.exe (v4.0.rc1)
dc6a82fc6cfda792d3182e07de10adbfba42bf336ef269dbc40732c4b2ae052c  winpmem_mini_x86.exe (v4.0.rc1)
093d1c6b91d280c9644635c667753e0aa0e78c656eb4082147bf30364787d96f  autorunsc64.exe (2026-06-17 빌드)
a2394a11272ae38e7fb6ea862e783daa6d704a3d9c73a51dfe978b7692df6b1f  autorunsc.exe (2026-06-17 빌드)
13f7ee6f51ab8d42a1d1e6812c00e174e88802412fbeaed98582c3cb443ab8ee  autorunsc64a.exe (2026-06-17 빌드)
```
