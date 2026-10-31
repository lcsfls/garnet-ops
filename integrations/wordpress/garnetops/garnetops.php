<?php
/**
 * Plugin Name:       GarnetOps
 * Plugin URI:        https://github.com/lcsfls/garnet-ops
 * Description:       Lets your GarnetOps installation read which WordPress, PHP, plugin and theme versions this site runs, so it can warn about outdated and vulnerable ones. Read-only; nothing is sent anywhere by this plugin.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            GarnetOps maintainers
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       garnetops
 *
 * @package GarnetOps
 */

/*
 * Copyright (C) GarnetOps maintainers
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 */

defined( 'ABSPATH' ) || exit;

define( 'GARNETOPS_VERSION', '1.0.0' );

require_once __DIR__ . '/includes/class-garnetops-inventory.php';
require_once __DIR__ . '/includes/class-garnetops-access.php';

/*
 * The one endpoint (ADR 0042, part 4): GarnetOps reads it during its daily look at the website. It answers only over HTTPS and
 * only with the token GarnetOps generated for this site. Reachable as /?rest_route=/garnetops/v1/inventory, with or without
 * pretty permalinks.
 */
add_action(
	'rest_api_init',
	static function () {
		register_rest_route(
			'garnetops/v1',
			'/inventory',
			array(
				'methods'             => 'GET',
				'permission_callback' => static function ( WP_REST_Request $request ) {
					// Some Apache and CGI setups drop Authorization; GarnetOps sends the token in its own header as well.
					$authorization = $request->get_header( 'authorization' );
					if ( ! $authorization && $request->get_header( 'x_garnetops_token' ) ) {
						$authorization = 'Bearer ' . $request->get_header( 'x_garnetops_token' );
					}
					return GarnetOps_Access::check( $authorization, is_ssl() );
				},
				'callback'            => static function () {
					$response = new WP_REST_Response( GarnetOps_Inventory::build(), 200 );
					$response->header( 'Cache-Control', 'no-store' );
					return $response;
				},
			)
		);
	}
);

/* The settings page: paste the token GarnetOps shows once, or remove it. Administrators only. */
add_action(
	'admin_menu',
	static function () {
		add_options_page( 'GarnetOps', 'GarnetOps', 'manage_options', 'garnetops', 'garnetops_settings_page' );
	}
);

/** Renders and handles the settings page. */
function garnetops_settings_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	$notice = '';
	if ( isset( $_POST['garnetops_action'] ) ) {
		check_admin_referer( 'garnetops_settings' );
		if ( 'remove' === $_POST['garnetops_action'] ) {
			GarnetOps_Access::remove_token();
			$notice = __( 'The token is removed. GarnetOps can no longer read this site.', 'garnetops' );
		} elseif ( 'save' === $_POST['garnetops_action'] ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- checked against a strict pattern.
			$token  = isset( $_POST['garnetops_token'] ) ? wp_unslash( $_POST['garnetops_token'] ) : '';
			$notice = GarnetOps_Access::set_token( $token )
				? __( 'Saved. GarnetOps reads this site at its next daily look.', 'garnetops' )
				: __( 'That is not a GarnetOps token. Copy it again from the website page in GarnetOps.', 'garnetops' );
		}
	}
	echo '<div class="wrap"><h1>GarnetOps</h1>';
	if ( '' !== $notice ) {
		echo '<div class="notice notice-info"><p>' . esc_html( $notice ) . '</p></div>';
	}
	echo '<p>' . esc_html__( 'GarnetOps reads which WordPress, PHP, plugin and theme versions this site runs. It sends nothing else: no users, no content, no settings. This plugin never sends anything by itself.', 'garnetops' ) . '</p>';
	if ( ! is_ssl() ) {
		echo '<div class="notice notice-warning"><p>' . esc_html__( 'GarnetOps reads the site over HTTPS only.', 'garnetops' ) . '</p></div>';
	}
	echo '<form method="post">';
	wp_nonce_field( 'garnetops_settings' );
	if ( GarnetOps_Access::has_token() ) {
		echo '<p>' . esc_html__( 'Connected: a token is set. Only its fingerprint is stored here.', 'garnetops' ) . '</p>';
		echo '<p><button class="button" name="garnetops_action" value="remove">' . esc_html__( 'Remove token', 'garnetops' ) . '</button></p>';
	}
	echo '<p><label for="garnetops_token">' . esc_html__( 'Token from GarnetOps', 'garnetops' ) . '</label><br />';
	echo '<input type="password" id="garnetops_token" name="garnetops_token" class="regular-text" autocomplete="off" spellcheck="false" /></p>';
	echo '<p><button class="button button-primary" name="garnetops_action" value="save">' . esc_html__( 'Save token', 'garnetops' ) . '</button></p>';
	echo '</form></div>';
}
