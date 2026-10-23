# syntax=docker/dockerfile:1.7
#
# GarnetOps images (ADR 0007), built by the release workflow per architecture:
#
#   --target app   API and worker (Node.js 24, runs the TypeScript sources directly
#                  with Node's type stripping), git and OpenSSH for clones, grype and
#                  syft with pinned SHA-256 checksums
#   --target web   the edge: Caddy serving the built web app, proxying /api and showing
#                  the update sidecar's maintenance page while the API is down
#
# Base images are pinned by digest (AGENTS.md rule 1). The build argument VERSION is
# the release version; it is baked in as APP_VERSION and the image's version label.

ARG NODE_IMAGE=node:24.22.1-alpine3.24@sha256:6a1c190e17215d844926b0677f4bf87273ff7d5e54db06d3b5b5863ab0b09a3d
ARG CADDY_IMAGE=caddy:2.11.7-alpine@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f

# ---------------------------------------------------------------- dependencies
FROM ${NODE_IMAGE} AS deps
# pnpm 12 needs a newer corepack than Node 24 ships.
RUN npm install --global --no-audit --no-fund corepack@0.36.0 && corepack enable
WORKDIR /src
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/api/package.json apps/api/
COPY apps/worker/package.json apps/worker/
COPY apps/web/package.json apps/web/
COPY packages/core/package.json packages/core/
COPY packages/db/package.json packages/db/
COPY packages/i18n/package.json packages/i18n/
COPY vendor vendor
RUN corepack pnpm install --frozen-lockfile

# ---------------------------------------------------------------- web build
FROM deps AS web-build
COPY tsconfig.base.json biome.json ./
COPY packages packages
COPY apps/web apps/web
RUN corepack pnpm --filter @garnetops/web build

# ---------------------------------------------------------------- production tree
FROM deps AS prod
RUN rm -rf node_modules apps/*/node_modules packages/*/node_modules \
 && corepack pnpm install --frozen-lockfile --prod --filter "@garnetops/api..." --filter "@garnetops/worker..."
COPY packages/core/src packages/core/src
COPY packages/db/src packages/db/src
COPY packages/db/drizzle packages/db/drizzle
COPY packages/i18n/src packages/i18n/src
COPY apps/api/src apps/api/src
COPY apps/worker/src apps/worker/src
COPY LICENSE LICENSING.md TRADEMARKS.md ./
# Only what runs: no web app sources, no vendored tarball (it is unpacked in node_modules), no tests.
RUN rm -rf apps/web vendor pnpm-lock.yaml pnpm-workspace.yaml \
 && find apps packages -name "*.test.ts" -delete

# ---------------------------------------------------------------- scanners
FROM ${NODE_IMAGE} AS scanners
WORKDIR /src
COPY scripts/fetch-scanners.mjs scripts/
# Downloads grype and syft and checks their pinned SHA-256 checksums (fails the build otherwise).
RUN node scripts/fetch-scanners.mjs
RUN mkdir -p /opt/scanners \
 && cp .tools/grype/grype .tools/syft/syft /opt/scanners/ \
 && cp .tools/grype/LICENSE /opt/scanners/LICENSE.grype \
 && cp .tools/syft/LICENSE /opt/scanners/LICENSE.syft

# ---------------------------------------------------------------- app: API and worker
FROM ${NODE_IMAGE} AS app
ARG VERSION=0.0.2
# git (GPL-2.0) and OpenSSH run as separate programs for clones, never linked (AGENTS.md rule 3).
# npm and corepack are not needed at run time.
RUN apk add --no-cache git openssh-client \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
      /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack
COPY --from=prod /src /app
COPY --from=scanners /opt/scanners /opt/scanners
WORKDIR /app
ENV NODE_ENV=production \
    APP_VERSION=${VERSION} \
    HOST=0.0.0.0 \
    PORT=3000 \
    GARNETOPS_GRYPE_BIN=/opt/scanners/grype \
    GARNETOPS_SYFT_BIN=/opt/scanners/syft \
    GARNETOPS_GRYPE_DB_DIR=/var/lib/garnetops/vulndb \
    GARNETOPS_WORK_DIR=/tmp/garnetops-work
RUN mkdir -p /var/lib/garnetops/vulndb /vault && chown node:node /var/lib/garnetops/vulndb /vault
LABEL org.opencontainers.image.title="GarnetOps" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/lcsfls/garnet-ops" \
      org.opencontainers.image.version="${VERSION}"
# The node user (uid and gid 1000); the update sidecar's token file is readable by gid 1000.
USER node
EXPOSE 3000
CMD ["node", "apps/api/src/index.ts"]

# ---------------------------------------------------------------- web: the edge
FROM ${CADDY_IMAGE} AS web
ARG VERSION=0.0.2
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY --from=web-build /src/apps/web/dist /srv
# Caddy listens on 8080 and 8443 as an unprivileged user, so its file capability to bind
# low ports is dropped (a copy loses it); with it, exec fails under no-new-privileges.
RUN cp /usr/bin/caddy /usr/bin/caddy.plain && mv /usr/bin/caddy.plain /usr/bin/caddy \
 && mkdir -p /data /config && chown -R 1000:1000 /data /config
LABEL org.opencontainers.image.title="GarnetOps web" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/lcsfls/garnet-ops" \
      org.opencontainers.image.version="${VERSION}"
USER 1000:1000
EXPOSE 8080 8443
