# Licensing

Copyright (c) 2026 IT Systeme Flores UG (haftungsbeschränkt).

GarnetOps is dual-licensed:

1. **GNU Affero General Public License v3.0 only** (`AGPL-3.0-only`), see
   [`LICENSE`](LICENSE). You may use, study, change and share GarnetOps, also
   as a hosted service, as long as you meet the AGPL's terms, in particular
   section 13: if you offer a modified version to users over a network, you
   must offer them its complete source code under the same license.
2. **A commercial license** for organisations that cannot or do not want to
   use AGPL software, or that need terms the AGPL does not give (for example
   keeping their changes private, warranty or indemnity). Contact
   IT Systeme Flores UG for terms; pricing on request.

Third-party components keep their own licenses; see
[`docs/COMPONENTS.md`](docs/COMPONENTS.md). The directory [`updater/`](updater/VENDORED.md) (the
optional update sidecar, taken from an Apache-2.0 project of the same copyright holder) stays under
the Apache-2.0 license in [`updater/LICENSE`](updater/LICENSE); the AGPL does not apply to it. The
GarnetOps WordPress plugin in [`integrations/wordpress/garnetops/`](integrations/wordpress/README.md) is our own code, a
separate program that runs inside WordPress, and is licensed under GPL-2.0-or-later as WordPress plugins must be
([`integrations/wordpress/garnetops/LICENSE`](integrations/wordpress/garnetops/LICENSE)); nothing of it is part of
GarnetOps itself.

The names "GarnetOps" and the GarnetOps logo and wordmark are not licensed
under the AGPL; see [`TRADEMARKS.md`](TRADEMARKS.md).

Background: [ADR 0006](docs/adr/0006-agpl-with-commercial-license.md).
