### Security

- **A repository's `.gitleaksignore` could hide secrets from the history check** (ADR 0049; 0.1.3 and 0.1.4). gitleaks also reads that file from the scanned directory, besides the empty one GarnetOps names, and in history mode its entries match. Anyone who could commit to a repository with the history check on could hide a secret in its history from GarnetOps. The file is now removed from the clone before gitleaks runs, and a run refuses to start while it is there. The check of the current files was not affected in practice (an entry there has to name the clone's random directory). Run a history check again on repositories where this matters (Repository → Secrets → **Check history now**).

### Added

- **Export of the Secrets page** ([docs/secrets.md](https://github.com/lcsfls/garnet-ops/blob/v0.1.5/docs/secrets.md#export)): CSV, Excel, PDF or text, as on the Findings page, with the filters that are set. It lists where each secret was found, never a value, and is audited.
- **Several secrets at once**: tick secrets (or all shown) and mark them as revoked, not a secret or reopen them with one reason; each one is audited on its own. Common reasons are one click away in the reason field.
- **Search** the secrets by rule or path.

### Changed

- The Secrets page is quicker to work through: the whole row opens a secret, closing the shown one moves on to the next, the detail and the bar of ticked secrets stay in view while the list scrolls, and on smaller screens the detail comes first.

Full list of changes: [CHANGELOG.md](https://github.com/lcsfls/garnet-ops/blob/v0.1.5/CHANGELOG.md)
