#!/usr/bin/env bash
# Local Canton (open-source, in-memory) for end-to-end tests: 1 sequencer, 1 mediator, 3 participants.
# Not LocalNet: no Splice apps, ~1.3 GB RAM. Usage: scripts/local-canton.sh start|stop|status
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${CANTON_VERSION:-3.5.19}"
CACHE="${CANTON_CACHE:-$HOME/.cache/cdz}"
DIST="$CACHE/canton-open-source-$VERSION"
RUN="$ROOT/tests/e2e/run"
case "${1:-}" in
  start)
    if [[ ! -x "$DIST/bin/canton" ]]; then
      mkdir -p "$CACHE"
      curl -fL "https://github.com/digital-asset/canton/releases/download/v$VERSION/canton-open-source-$VERSION.tar.gz" \
        | tar xz -C "$CACHE"
    fi
    mkdir -p "$RUN"; rm -f "$RUN"/{ready,synchronizer_id,participants,canton_ports.json}
    cp "$ROOT/tests/e2e/canton/"* "$RUN/"
    (cd "$RUN" && JAVA_OPTS="${JAVA_OPTS:--Xms512m -Xmx2g -XX:+UseSerialGC}" nohup "$DIST/bin/canton" daemon \
        -c e2e.conf --bootstrap bootstrap.canton --log-file-name canton.log > canton.out 2>&1 & echo $! > canton.pid)
    for _ in $(seq 1 60); do [[ -f "$RUN/ready" ]] && { echo "canton ready ($RUN)"; exit 0; }; sleep 3; done
    echo "canton did not start, see $RUN/canton.log" >&2; exit 1 ;;
  stop)
    [[ -f "$RUN/canton.pid" ]] && pkill -P "$(cat "$RUN/canton.pid")" 2>/dev/null; kill "$(cat "$RUN/canton.pid")" 2>/dev/null || true
    rm -f "$RUN/canton.pid" "$RUN/ready"; echo stopped ;;
  status)
    [[ -f "$RUN/ready" ]] && echo "running: $(cat "$RUN/synchronizer_id")" || echo "not running" ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
