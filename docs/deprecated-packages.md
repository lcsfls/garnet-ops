# Deprecated and yanked packages

A module (Settings → Modules → **Deprecated packages**, off by default) that shows which packages in your repositories their
maintainers have **deprecated** (npm: "no longer supported", "use X instead") or **yanked** (PyPI, crates.io: a version withdrawn,
often for a serious bug). This is the information behind `npm warn deprecated` during `npm ci`. It is not in any vulnerability
database, so GarnetOps asks the package registries (ADR 0051).

## What leaves the network

Once the module is on, the worker sends **package names** (and for PyPI the version) to one registry per ecosystem:

| Ecosystem | Public registry | What is asked |
| --- | --- | --- |
| npm | `https://registry.npmjs.org` | the abbreviated package document; each version's `deprecated` message |
| PyPI | `https://pypi.org` | `/pypi/{name}/{version}/json`; yanked when every file of the version is |
| crates.io | `https://index.crates.io` | the crate's sparse index file; each version's `yanked` flag |

Nothing about repositories, organisations or people is sent, and the `User-Agent` is a fixed text.

- **Your own registry** (Verdaccio, Nexus, Artifactory, devpi, a crates.io index mirror) can replace a public one: an
  `https://` address, which may be in your own network. Loopback, link-local and cloud metadata addresses are always refused,
  and redirects are not followed. A registry with a certificate from your own CA needs that CA in the worker's trust store
  (`NODE_EXTRA_CA_CERTS`).
- **Never send**: npm scopes (`@acme`) and name patterns (`acme-*`) for your internal packages. They are not asked and show as not
  checked.
- Admins change these settings with a recent sign-in; each change is audited. Changing a registry forgets what the previous own
  registry said.
- Air-gapped installations use the module only with own registries.

## When

After every scan (only names that are new or whose answer is older than 24 hours) and once a day for everything, four requests at
a time and at most 2,000 names a run. **Check now** in the module's settings asks at once (once every ten minutes). A registry
that does not answer is shown with its reason under the settings; its packages count as not checked, never as fine.

## Where it shows

- **Packages**: the filter **Deprecated or yanked**, and on each such package the registry's message (as text).
- **Repository**: a card with its deprecated and yanked packages.
- **Quality gates**: the rule **Deprecated or yanked package**, **off** by default; set to Report or Block it counts the checked
  commit's packages known to be deprecated or yanked ([quality-gates.md](quality-gates.md)). A package GarnetOps has not asked
  about yet does not count.

Deprecated packages are not findings: they have no severity and do not change a repository's grade.

## API

`GET /api/v1/deprecated/settings`, `PUT /api/v1/deprecated/settings` with `{ "registries": { "npm", "pypi", "crates" },
"excluded": [...] }` (admins, recent sign-in), `POST /api/v1/deprecated/check`, `GET /api/v1/deprecated/repositories/{id}`;
`GET /api/v1/packages?deprecated=1`, and each package's `deprecation` (`{ "state": "deprecated" | "yanked", "message" }` or null).
The module is switched with `PUT /api/v1/organization/modules/deprecated`.
