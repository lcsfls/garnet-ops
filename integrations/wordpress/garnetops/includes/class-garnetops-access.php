<?php
/**
 * Who may read the inventory: only a request over HTTPS that carries the token GarnetOps generated for this website. The token
 * itself is never stored here, only its SHA-256, and it is compared in constant time.
 *
 * @package GarnetOps
 */

defined( 'ABSPATH' ) || exit;

/**
 * The token check of the inventory endpoint.
 */
final class GarnetOps_Access {

	/** The option that holds the token's SHA-256 (hex). */
	const OPTION = 'garnetops_token_sha256';

	/** Wrong tokens allowed per ten minutes before wrong tokens get 429 instead of 401. */
	const MAX_FAILURES = 20;

	/** Tokens as GarnetOps generates them: 43 characters of base64url (32 random bytes). */
	const TOKEN_PATTERN = '/^[A-Za-z0-9_-]{43}$/';

	/**
	 * Stores the SHA-256 of a token pasted by an administrator. Returns false for something that is not a token.
	 *
	 * @param string $token The token as GarnetOps showed it.
	 * @return bool
	 */
	public static function set_token( $token ) {
		$token = trim( (string) $token );
		if ( 1 !== preg_match( self::TOKEN_PATTERN, $token ) ) {
			return false;
		}
		update_option( self::OPTION, hash( 'sha256', $token ), false );
		return true;
	}

	/** Forgets the token: the endpoint answers nobody until a new one is set. */
	public static function remove_token() {
		delete_option( self::OPTION );
	}

	/** @return bool Whether a token is set. */
	public static function has_token() {
		$stored = get_option( self::OPTION, '' );
		return is_string( $stored ) && 64 === strlen( $stored );
	}

	/**
	 * Whether a request may read the inventory. Answers a WP_Error with the status to send otherwise.
	 *
	 * @param string|null $authorization The Authorization header.
	 * @param bool        $secure        Whether the request came over HTTPS.
	 * @return true|WP_Error
	 */
	public static function check( $authorization, $secure ) {
		if ( ! $secure ) {
			return new WP_Error( 'garnetops_https_required', 'HTTPS required.', array( 'status' => 403 ) );
		}
		$stored = get_option( self::OPTION, '' );
		$token  = '';
		if ( is_string( $authorization ) && 1 === preg_match( '/^Bearer ([A-Za-z0-9_-]{43})$/', trim( $authorization ), $m ) ) {
			$token = $m[1];
		}
		if ( is_string( $stored ) && 64 === strlen( $stored ) && '' !== $token
			&& hash_equals( $stored, hash( 'sha256', $token ) ) ) {
			return true;
		}
		// Wrong tokens are slowed down, never the right one: guessing is pointless against 256 random bits, and a lock for
		// everybody would let anyone keep GarnetOps out.
		$failures = (int) get_transient( 'garnetops_failures' );
		if ( $failures >= self::MAX_FAILURES ) {
			return new WP_Error( 'garnetops_rate_limited', 'Too many attempts.', array( 'status' => 429 ) );
		}
		set_transient( 'garnetops_failures', $failures + 1, 10 * MINUTE_IN_SECONDS );
		return new WP_Error( 'garnetops_unauthorized', 'Unauthorized.', array( 'status' => 401 ) );
	}
}
