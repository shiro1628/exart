# 변경 내역

## 미출시
- Windows: 잠긴 파일 복사와 $MFT 대체 수집에서 forecopy_handy를 뺐다(공식 배포처 없음).
  잠긴 파일은 The Sleuth Kit `icat`으로 파일 ID(MFT 엔트리 번호)를 지정해 볼륨에서 직접 읽는다.
- Windows: $MFT 보조 수집. icat이 없거나 실패하면 VSS 섀도 사본을 임시로 만들어 내장 NTFS 파서
  (`exart/ntfs_raw.py`, 조각난 $MFT·$ATTRIBUTE_LIST 지원)로 읽고 섀도 사본을 지운다.
- 외부 도구 다운로드 링크와 빌드 가이드(`docs/BUILD.md`)를 추가했다.
- 외부 도구 배치 가이드(`docs/TOOLS.md`): 파일 이름, 찾는 순서, 없을 때의 동작, 확인 방법.

## 2.0.0
- Windows·macOS·Linux 수집기를 공통 코어 위에 다시 작성. 표준 라이브러리만 사용(Python 3.6+).
- 증거 무결성: 파일별 원본 메타데이터·SHA-256·MD5(manifest.jsonl), 명령 기록(commands.jsonl),
  결과 전체 SHA256SUMS, `--verify` 로 대조.
- 시스템 볼륨에 결과를 쓰려 하면 경고 후 중단.
- Linux: `/proc` 직접 해석, 삭제된 채 실행 중인 실행 파일 복구, `--fs-root` 로 `kubectl debug` 대상 수집.
- 클라우드 동기화 자리표시자 파일(OneDrive·iCloud)은 읽지 않음.
- 결과 이름이 겹치면 덮어쓰지 않고 접미사를 붙임.
- 단일 폴더(onedir) 배포 빌드 스크립트(macOS, Linux, Windows via Wine).
