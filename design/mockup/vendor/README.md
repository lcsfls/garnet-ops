# Vendored third-party assets

Self-hosted copies so the mockup loads nothing from external servers
(see AGENTS.md, rule 3). License texts are in `licenses/`. The full register
of all components lives in `docs/COMPONENTS.md`.

| Asset | Version | License | Use |
|---|---|---|---|
| Inter Tight (latin, latin-ext; 400–700) | 5.x via Fontsource | SIL OFL 1.1 | UI font (as in Restow) |
| IBM Plex Mono (latin, latin-ext; 400, 500) | 5.x via Fontsource | SIL OFL 1.1 | Monospace font (as in Restow) |
| Lucide | 0.469.0 | ISC (portions MIT, Feather) | Icons |
| d3 | 7.9.0 | ISC | Globe projection |
| topojson-client | 3.1.0 | ISC | Map data decoding |
| world-atlas countries-110m | 2.0.2 | ISC; data from Natural Earth (public domain) | Globe map (wrapped as `js/countries-110m.js` so it loads from `file://`) |

Note: brand icons (e.g. GitHub) are trademarks of their owners; review before
production use.
