# GarnetOps

Self-hosted security platform for SecOps teams and everyday sysadmins:
repository quality gates, dependency and container update checks, host
monitoring and an XDR view via Wazuh, with AI triage on the customer's own
OpenAI-compatible model. No code, finding or log leaves the customer's network.

Dual-licensed: [AGPL-3.0-only](LICENSE) and a commercial license
([LICENSING.md](LICENSING.md)). Domain: garnetops.com.

**Status:** early development, no release yet. Working today: sign-in with
mandatory TOTP, repositories over HTTPS or SSH (generated deploy keys),
dependency scanning with syft and grype on a local vulnerability database,
findings with CVSS/EPSS and export (CSV, XLSX, PDF, text), repository pages with
scan and patch history, package inventory, nightly scans, audit log, a Docker
Compose stack and optional signed in-app updates.

- Install: [docs/installation.md](docs/installation.md)
- Update: [docs/updating.md](docs/updating.md)

- Security reports: [SECURITY.md](SECURITY.md) (please not as a public issue)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)

- Rules for contributors and AI agents: [AGENTS.md](AGENTS.md)
- Roadmap: [ROADMAP.md](ROADMAP.md)
- Changes: [CHANGELOG.md](CHANGELOG.md)
- Components and licenses: [docs/COMPONENTS.md](docs/COMPONENTS.md)
- Architecture decisions: [docs/adr/](docs/adr/)
- Visual mockup: [design/mockup/mockup.html](design/mockup/mockup.html) (open in a browser, works offline)
