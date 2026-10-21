#!/bin/sh
# Creates .env for a new GarnetOps installation (docs/installation.md):
#   deploy/install.sh <host name> [app image] [web image]
# Generates the database password and the session secret, sets PROJECT_DIR to this
# directory, and refuses to touch an existing .env (it holds the secrets of a running
# installation).
set -eu

host="${1:?usage: deploy/install.sh <host name, e.g. garnetops.example.lan> [app image] [web image]}"
app_image="${2:-}"
web_image="${3:-}"
dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$dir"

if [ -e .env ]; then
  echo "install: .env exists; it holds the secrets of this installation. Nothing was changed." >&2
  exit 1
fi
case "$host" in
  *[!A-Za-z0-9.-]* | "") echo "install: not a host name: $host" >&2; exit 1 ;;
esac

secret() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }

umask 077
sed \
  -e "s|^PUBLIC_URL=.*|PUBLIC_URL=https://$host|" \
  -e "s|^GARNETOPS_HOST=.*|GARNETOPS_HOST=$host|" \
  -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(secret)|" \
  -e "s|^BETTER_AUTH_SECRET=.*|BETTER_AUTH_SECRET=$(secret)|" \
  -e "s|^PROJECT_DIR=.*|PROJECT_DIR=$dir|" \
  .env.example > .env
[ -n "$app_image" ] && sed -i "s|^APP_IMAGE=.*|APP_IMAGE=$app_image|" .env
[ -n "$web_image" ] && sed -i "s|^WEB_IMAGE=.*|WEB_IMAGE=$web_image|" .env
chmod 600 .env

echo "install: wrote .env for https://$host (mode 0600)."
echo "Next: check APP_IMAGE and WEB_IMAGE in .env, then run: docker compose up -d"
echo "The API prints a one-time setup token: docker compose logs api"
