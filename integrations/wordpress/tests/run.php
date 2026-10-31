<?php
/**
 * Tests of the GarnetOps WordPress plugin without WordPress: the few WordPress functions it uses are stubbed with in-memory
 * versions. Run with `php tests/run.php`; exits non-zero on the first failure.
 */

define( 'ABSPATH', __DIR__ . '/' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'GARNETOPS_VERSION', '1.0.0' );

// ---------------------------------------------------------------------------------------------------------------- stubs

$GLOBALS['options']    = array();
$GLOBALS['transients'] = array();

class WP_Error {
	public $code;
	public $data;
	public function __construct( $code, $message, $data ) {
		$this->code = $code;
		$this->data = $data;
	}
}
class Fake_Theme {
	private $version;
	public function __construct( $version ) {
		$this->version = $version;
	}
	public function get( $key ) {
		return 'Version' === $key ? $this->version : '';
	}
}
function get_option( $name, $fallback = false ) {
	return array_key_exists( $name, $GLOBALS['options'] ) ? $GLOBALS['options'][ $name ] : $fallback;
}
function update_option( $name, $value, $autoload = null ) {
	$GLOBALS['options'][ $name ] = $value;
	return true;
}
function delete_option( $name ) {
	unset( $GLOBALS['options'][ $name ] );
	return true;
}
function get_transient( $name ) {
	return $GLOBALS['transients'][ $name ] ?? false;
}
function set_transient( $name, $value, $ttl ) {
	$GLOBALS['transients'][ $name ] = $value;
	return true;
}
function is_multisite() {
	return false;
}
function get_site_option( $name, $fallback = false ) {
	return $fallback;
}
function get_plugins() {
	return array(
		'contact-form-7/wp-contact-form-7.php' => array( 'Name' => 'Contact Form 7', 'Version' => '5.9.3' ),
		'akismet/akismet.php'                  => array( 'Name' => 'Akismet', 'Version' => '5.3.1' ),
		'hello.php'                            => array( 'Name' => 'Hello Dolly', 'Version' => '1.7.2' ),
	);
}
function get_stylesheet() {
	return 'astra-child';
}
function get_template() {
	return 'astra';
}
function wp_get_themes() {
	return array(
		'astra'           => new Fake_Theme( '4.6.0' ),
		'astra-child'     => new Fake_Theme( '1.0.0' ),
		'twentytwentyfour' => new Fake_Theme( '1.2' ),
	);
}
function get_bloginfo( $what ) {
	return 'version' === $what ? '6.5.2' : '';
}

require __DIR__ . '/../garnetops/includes/class-garnetops-inventory.php';
require __DIR__ . '/../garnetops/includes/class-garnetops-access.php';

// -------------------------------------------------------------------------------------------------------------- helpers

$failures = 0;
function check( $name, $condition ) {
	global $failures;
	if ( $condition ) {
		echo "ok   $name\n";
	} else {
		echo "FAIL $name\n";
		++$failures;
	}
}

// ---------------------------------------------------------------------------------------------------------------- tests

$token = rtrim( strtr( base64_encode( random_bytes( 32 ) ), '+/', '-_' ), '=' );

check( 'refuses anything that is not a token', ! GarnetOps_Access::set_token( 'short' ) && ! GarnetOps_Access::has_token() );
check( 'stores only the SHA-256 of a token', GarnetOps_Access::set_token( " $token \n" )
	&& get_option( GarnetOps_Access::OPTION ) === hash( 'sha256', $token )
	&& false === strpos( serialize( $GLOBALS['options'] ), $token ) );

$denied = GarnetOps_Access::check( "Bearer $token", false );
check( 'answers 403 without HTTPS, even with the right token', $denied instanceof WP_Error && 403 === $denied->data['status'] );
check( 'lets the right token in over HTTPS', true === GarnetOps_Access::check( "Bearer $token", true ) );
$wrong = GarnetOps_Access::check( 'Bearer ' . str_repeat( 'A', 43 ), true );
check( 'answers 401 for a wrong token', $wrong instanceof WP_Error && 401 === $wrong->data['status'] );
check( 'answers 401 without a header', GarnetOps_Access::check( null, true ) instanceof WP_Error );
check( 'answers 401 for another scheme', GarnetOps_Access::check( "Basic $token", true ) instanceof WP_Error );

for ( $i = 0; $i < GarnetOps_Access::MAX_FAILURES; $i++ ) {
	GarnetOps_Access::check( 'Bearer ' . str_repeat( 'B', 43 ), true );
}
$limited = GarnetOps_Access::check( 'Bearer ' . str_repeat( 'C', 43 ), true );
check( 'answers 429 to wrong tokens after repeated wrong ones', $limited instanceof WP_Error && 429 === $limited->data['status'] );
check( 'still lets the right token in, so nobody can lock GarnetOps out', true === GarnetOps_Access::check( "Bearer $token", true ) );
$GLOBALS['transients'] = array();

GarnetOps_Access::remove_token();
check( 'answers nobody once the token is removed', GarnetOps_Access::check( "Bearer $token", true ) instanceof WP_Error );

$GLOBALS['options']['active_plugins'] = array( 'contact-form-7/wp-contact-form-7.php' );
$inventory = GarnetOps_Inventory::build();
check( 'names WordPress and PHP', '6.5.2' === $inventory['wordpress'] && 1 === preg_match( '/^\d+\.\d+\.\d+$/', $inventory['php'] ) );
check( 'lists plugins by slug with version and state', array(
	array( 'slug' => 'contact-form-7', 'version' => '5.9.3', 'active' => true ),
	array( 'slug' => 'akismet', 'version' => '5.3.1', 'active' => false ),
	array( 'slug' => 'hello', 'version' => '1.7.2', 'active' => false ),
) === $inventory['plugins'] );
check( 'marks the active theme and its parent', array(
	array( 'slug' => 'astra', 'version' => '4.6.0', 'active' => true ),
	array( 'slug' => 'astra-child', 'version' => '1.0.0', 'active' => true ),
	array( 'slug' => 'twentytwentyfour', 'version' => '1.2', 'active' => false ),
) === $inventory['themes'] );
check( 'says nothing else', array( 'schema', 'plugin', 'pluginVersion', 'wordpress', 'php', 'plugins', 'themes' ) === array_keys( $inventory ) );

echo $failures ? "\n$failures failed\n" : "\nall passed\n";
exit( $failures ? 1 : 0 );
