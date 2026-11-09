#!/usr/bin/env bash
# A throwaway PostgreSQL cluster for the axon-gateway test suite, tuned for speed.
#
#   scripts/test-pg.sh start                 start (or reuse) and print `export` lines
#   scripts/test-pg.sh stop                  stop the cluster, remove its files
#   scripts/test-pg.sh run -- <command...>   start, run, stop (only if it started it)
#
# The root justfile uses `start` and `stop` (axon-db-up, axon-db-down). The
# cluster lives at a fixed path, so `start` and `stop` in separate invocations
# find the same one. `start` on a cluster that is already up only prints the URL.
#
# The URL is a unix-socket URL for the `axon` role and database:
#   postgres://axon@localhost/axon?host=$XDG_RUNTIME_DIR/axon-test-pg-<uid>
# The justfile builds the same path (axon_db_url), so keep the two in step.
#
# WHY IT IS FAST:
# - The data directory lives on tmpfs ($XDG_RUNTIME_DIR, else /tmp). Nothing
#   touches the disk.
# - Durability is switched off: fsync, synchronous_commit, full_page_writes,
#   and WAL down to `minimal`. A crash loses the cluster, which is thrown away
#   at the end of the run anyway.
# - Autovacuum, JIT and checkpoints are out of the way.
# - Unix socket only (`listen_addresses = ''`): no TCP port to collide with a
#   developer's own Postgres, or with a parallel gate.
#
# The `axon` role is a superuser, so tests can create their own databases.
# Auth is `trust`, so the socket directory is per-user and mode 0700: nobody
# else on the machine can reach the cluster, even under the shared /tmp.
set -euo pipefail
umask 077

dir="${XDG_RUNTIME_DIR:-/tmp}/axon-test-pg-$(id -u)"
data="$dir/data"
url="postgres://axon@localhost/axon?host=$dir"

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: '$1' not found; PostgreSQL must be on PATH (it is in the nix dev shell)" >&2
        exit 1
    }
}

ready() {
    pg_isready -q -h "$dir" >/dev/null 2>&1
}

start() {
    need initdb
    need pg_ctl
    need pg_isready
    need createdb

    if ready; then
        echo "export AXON_TEST_DATABASE_URL='$url'"
        return 0
    fi

    # Not answering: a leftover from a run that died. Stop it if it still runs,
    # then start clean.
    if [ -d "$data" ]; then
        pg_ctl -D "$data" -m immediate stop >/dev/null 2>&1 || true
    fi
    rm -rf "$dir"
    # No -p: fail rather than reuse a directory someone else created.
    mkdir -m 700 "$dir"

    initdb -D "$data" -U axon -A trust --no-sync --no-instructions \
        --no-locale -E UTF8 >"$dir/initdb.log" 2>&1 || {
        cat "$dir/initdb.log" >&2
        exit 1
    }

    cat >>"$data/postgresql.conf" <<EOF
listen_addresses = ''
unix_socket_directories = '$dir'
unix_socket_permissions = 0700
max_connections = 300
shared_buffers = 128MB
fsync = off
synchronous_commit = off
full_page_writes = off
wal_level = minimal
max_wal_senders = 0
max_wal_size = 4GB
checkpoint_timeout = 1d
autovacuum = off
jit = off
dynamic_shared_memory_type = mmap
log_min_messages = warning
EOF

    pg_ctl -D "$data" -l "$dir/postgres.log" -w -t 30 start >/dev/null || {
        cat "$dir/postgres.log" >&2
        exit 1
    }

    for _ in $(seq 1 30); do
        ready && break
        sleep 1
    done
    ready || {
        echo "timed out waiting for postgres" >&2
        cat "$dir/postgres.log" >&2
        exit 1
    }

    createdb -h "$dir" -U axon axon
    echo "export AXON_TEST_DATABASE_URL='$url'"
}

stop() {
    [ -d "$dir" ] || return 0
    pg_ctl -D "$data" -m immediate stop >/dev/null 2>&1 || true
    rm -rf "$dir"
}

case "${1:-}" in
start) start ;;
stop) stop ;;
run)
    shift
    [ "${1:-}" = "--" ] && shift
    [ $# -gt 0 ] || { echo "usage: $0 run -- <command...>" >&2; exit 2; }
    # Stop only a cluster this run started: one already up belongs to someone else.
    if ! ready; then
        trap stop EXIT INT TERM
    fi
    eval "$(start)"
    "$@"
    ;;
*)
    echo "usage: $0 {run -- <command...>|start|stop}" >&2
    exit 2
    ;;
esac
