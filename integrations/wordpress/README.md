# GarnetOps WordPress plugin

The WordPress plugin of [ADR 0042](../../docs/adr/0042-wordpress-plugins-and-themes.md), part 4: it lets a GarnetOps installation
read the exact WordPress, PHP, plugin and theme versions of a site. See `garnetops/readme.txt` for what it does and
[docs/websites.md](../../docs/websites.md) for how GarnetOps uses it.

**Licence:** this directory is licensed under GPL-2.0-or-later (`garnetops/LICENSE`), as WordPress plugins must be. It is our own
code, a separate program that runs inside WordPress; it is not part of GarnetOps itself and nothing of it is linked into
GarnetOps. GarnetOps serves it as a zip for download.

Tests: `php tests/run.php` (PHP 7.4 or later, no WordPress needed: the few WordPress functions used are stubbed).
