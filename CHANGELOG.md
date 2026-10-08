# 변경 내역

## 2.0.0
- Windows·macOS·Linux 수집기를 공통 코어 위에 다시 작성. 표준 라이브러리만 사용(Python 3.6+).
- 증거 무결성: 파일별 원본 메타데이터·SHA-256·MD5(manifest.jsonl), 명령 기록(commands.jsonl),
  결과 전체 SHA256SUMS, `--verify` 로 대조.
- 시스템 볼륨에 결과를 쓰려 하면 경고 후 중단.
- Linux: `/proc` 직접 해석, 삭제된 채 실행 중인 실행 파일 복구, `--fs-root` 로 `kubectl debug` 대상 수집.
- 클라우드 동기화 자리표시자 파일(OneDrive·iCloud)은 읽지 않음.
- 결과 이름이 겹치면 덮어쓰지 않고 접미사를 붙임.
- 단일 폴더(onedir) 배포 빌드 스크립트(macOS, Linux, Windows via Wine).
