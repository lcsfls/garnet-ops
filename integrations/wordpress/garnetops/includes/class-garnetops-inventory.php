<?php
/**
 * What this WordPress installation runs: its version, the PHP version, and every installed plugin and theme with its version
 * and whether it is active. Nothing else: no users, no content, no settings, no paths.
 *
 * @package GarnetOps
 */

defined( 'ABSPATH' ) || exit;

/**
 * Builds the inventory GarnetOps reads (ADR 0042, part 4).
 */
final class GarnetOps_Inventory {

	/** The answer's format; GarnetOps refuses one it does not know. */
	const SCHEMA = 1;

	/**
	 * The inventory as an array, ready for JSON.
	 *
	 * @return array<string, mixed>
	 */
	public static function build() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$active  = (array) get_option( 'active_plugins', array() );
		$network = is_multisite() ? array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) : array();
		$plugins = array();
		foreach ( get_plugins() as $file => $data ) {
			$plugins[] = array(
				'slug'    => self::plugin_slug( $file ),
				'version' => isset( $data['Version'] ) ? (string) $data['Version'] : '',
				'active'  => in_array( $file, $active, true ) || in_array( $file, $network, true ),
			);
		}
		$current = get_stylesheet();
		$parent  = get_template();
		$themes  = array();
		foreach ( wp_get_themes() as $slug => $theme ) {
			$themes[] = array(
				'slug'    => (string) $slug,
				'version' => (string) $theme->get( 'Version' ),
				'active'  => $slug === $current || $slug === $parent,
			);
		}
		return array(
			'schema'        => self::SCHEMA,
			'plugin'        => 'garnetops',
			'pluginVersion' => GARNETOPS_VERSION,
			'wordpress'     => (string) get_bloginfo( 'version' ),
			'php'           => self::php_version(),
			'plugins'       => $plugins,
			'themes'        => $themes,
		);
	}

	/**
	 * The directory of a plugin, which is its slug on wordpress.org; a single-file plugin is named after its file.
	 *
	 * @param string $file Plugin file relative to the plugins directory.
	 * @return string
	 */
	public static function plugin_slug( $file ) {
		$dir = dirname( $file );
		return '.' === $dir ? basename( $file, '.php' ) : $dir;
	}

	/**
	 * The PHP version without build suffixes ("8.2.12-1+deb12u1" becomes "8.2.12").
	 *
	 * @return string
	 */
	public static function php_version() {
		return sprintf( '%d.%d.%d', PHP_MAJOR_VERSION, PHP_MINOR_VERSION, PHP_RELEASE_VERSION );
	}
}
