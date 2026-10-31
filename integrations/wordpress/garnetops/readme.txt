=== GarnetOps ===
Contributors: garnetops
Tags: security, inventory, vulnerabilities
Requires at least: 6.0
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lets your own GarnetOps installation read which WordPress, PHP, plugin and theme versions this site runs.

== Description ==

GarnetOps is a self-hosted security tool. With this plugin, the GarnetOps installation of your organisation can read the exact
versions of WordPress, PHP and every installed plugin and theme of this site during its daily look, and warn about outdated and
vulnerable ones.

* Read-only. The plugin adds one endpoint and never sends anything by itself.
* The endpoint answers only over HTTPS and only with the token your GarnetOps installation generated for this site. Only the
  token's SHA-256 is stored, and it is compared in constant time; repeated wrong tokens are slowed down, the right one never is.
* It answers with versions only: no users, no content, no settings, no file paths.

== Installation ==

1. In GarnetOps, open the website and choose "Connect the WordPress plugin". Download the plugin there and copy the token.
2. In WordPress, upload the plugin under Plugins → Add New → Upload Plugin and activate it.
3. Under Settings → GarnetOps, paste the token and save.

GarnetOps reads the site at its next daily look, or when you choose "Check now".

== Changelog ==

= 1.0.0 =
* First release.
