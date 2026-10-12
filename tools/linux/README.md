# Linux 외부 도구

없어도 exart는 돈다. 라이선스·용량 때문에 저장소에는 넣지 않으니 공식 배포처에서 받아 이 폴더에 둔다.

| 파일 | 쓰는 모듈 | 출처 |
|---|---|---|
| `avml` (x86_64), `avml-aarch64` | memory (`--memory`) | [Microsoft AVML v0.20.0](https://github.com/microsoft/avml/releases/tag/v0.20.0). 정적 링크라 배포판과 무관 |

avml 0.15 이후는 `avml acquire <파일>` 형식이다(exart가 `--help`로 판별). root와 CAP_SYS_ADMIN이 필요하고,
커널 lockdown이나 일반 컨테이너에서는 실패한다.

검증에 쓴 SHA-256 (v0.20.0):
```
a67010b08af2edf5a04d2f051a133e0d8e30853c308f055b8335e759609d6dc9  avml
d3fa9285e94ad4268cb7ed20a62d8bd7b1ac4561e191b8a82654864b4541b3ad  avml-aarch64
```
