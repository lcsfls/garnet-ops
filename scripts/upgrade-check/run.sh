#!/bin/sh
# The upgrade test's data check (AGENTS.md rule 2): "seed" puts example rows into the release before, "verify" checks after the
# upgrade that they are all still there, that every migration of this checkout ran, and that the API and the worker run.
# Called by the release smoke test (.github/workflows/release.yml) with $CICD_UPDATER_SMOKE_COMPOSE, a script that runs
# docker compose for the smoke's stack.
set -eu
here=$(dirname "$0")
compose=${CICD_UPDATER_SMOKE_COMPOSE:?run by the smoke test, which sets CICD_UPDATER_SMOKE_COMPOSE}
psql() {
  "$compose" exec -T db psql -U garnetops -d garnetops -v ON_ERROR_STOP=1 -X -q -t -A "$@"
}
case "${1:-}" in
  seed)
    psql < "$here/seed.sql"
    ;;
  verify)
    psql < "$here/verify.sql"
    expected=$(grep -c '"tag"' "$here/../../packages/db/drizzle/meta/_journal.json")
    applied=$(psql -c 'select count(*) from drizzle.__drizzle_migrations')
    if [ "$applied" != "$expected" ]; then
      echo "migrations: $applied applied, this release has $expected" >&2
      exit 1
    fi
    for service in api worker; do
      if ! "$compose" ps --status running --services | grep -qx "$service"; then
        echo "$service is not running after the upgrade" >&2
        "$compose" logs --tail 50 "$service" >&2 || true
        exit 1
      fi
    done
    echo "upgrade kept the data; $applied of $expected migrations applied; api and worker running"
    ;;
  *)
    echo "usage: $0 seed|verify" >&2
    exit 2
    ;;
esac
