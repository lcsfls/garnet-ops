<?php
/**
 * Removing the plugin removes the token fingerprint and the failure counter; nothing else is stored.
 *
 * @package GarnetOps
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

delete_option( 'garnetops_token_sha256' );
delete_transient( 'garnetops_failures' );
