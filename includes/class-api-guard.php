<?php
/**
 * API auth interception.
 *
 * Two responsibilities:
 *   1. Enforce 2FA on REST API and XML-RPC authentication. WordPress's standard
 *      auth filter chain happily lets app-password and XML-RPC requests succeed
 *      without ever prompting for a TOTP code — bypassing the browser-flow 2FA
 *      we wired into DSM_Two_Factor. For users in a 2FA-required role
 *      who attempt to auth via API, we return WP_Error so the request fails.
 *
 *   2. Optional: 404 the public-facing /wp-json and /xmlrpc.php paths entirely.
 *      Useful for sites that don't use REST/XML-RPC and want to narrow the
 *      attack surface. Off by default — turning this on breaks plugins that
 *      depend on REST internally (e.g. block editor, Gutenberg).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class DSM_API_Guard {

	public function boot(): void {
		// Priority 97: sits between throttle (96) and the browser-flow 2FA (100).
		// Only acts when WP has already returned a successful WP_User AND the
		// request is from an API context.
		add_filter( 'authenticate', [ $this, 'block_api_for_2fa_users' ], 97, 3 );

		// Pure URL-hiding for the API endpoints — runs on setup_theme like the
		// hidden-login engine so the response is decided before WP routes the request.
		add_action( 'setup_theme', [ $this, 'maybe_block_api_paths' ], 2 );
	}

	/**
	 * If the auth filter chain produced a valid WP_User AND we're in an API
	 * context (XML-RPC or REST) AND that user must have 2FA, reject the request.
	 * The user has to log in via the browser flow to get a session — there's no
	 * way to prompt for a TOTP code over XML-RPC or REST auth.
	 */
	public function block_api_for_2fa_users( $user, $username, $password ) {
		if ( ! $user instanceof WP_User ) {
			return $user;
		}
		if ( ! self::is_api_request() ) {
			return $user;
		}
		if ( ! DSM_Two_Factor::user_must_have_2fa( $user ) ) {
			return $user;
		}

		DSM_Activity_Log::record( DSM_Activity_Log::EVT_2FA_FAILED, [
			'user_id'  => $user->ID,
			'username' => $user->user_login,
			'details'  => [
				'reason'  => 'api_blocked',
				'context' => self::api_context_label(),
			],
		] );

		return new WP_Error(
			'dsm_api_2fa_required',
			__( '<strong>API access denied.</strong> Two-factor authentication is required for your account; XML-RPC and REST API auth cannot complete the 2FA challenge. Use the browser login flow.', 'defyn-security-manager' )
		);
	}

	/**
	 * If `hide_rest_api` / `hide_xmlrpc` options are on, serve a 404 (or redirect /
	 * decoy per blocked_response setting) for those URL prefixes. Same response
	 * behavior as a /wp-admin probe — makes the path indistinguishable from a
	 * site that genuinely doesn't have REST/XML-RPC routed.
	 */
	public function maybe_block_api_paths(): void {
		$hide_rest    = (bool) DSM_Options::get( 'hide_rest_api' );
		$hide_xmlrpc  = (bool) DSM_Options::get( 'hide_xmlrpc' );
		if ( ! $hide_rest && ! $hide_xmlrpc ) {
			return;
		}

		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/';
		$path = wp_parse_url( $uri, PHP_URL_PATH ) ?: '/';
		// Normalize home_url prefix the same way the hidden-login engine does.
		$home = wp_parse_url( home_url( '/' ), PHP_URL_PATH ) ?: '/';
		$home = '/' . trim( $home, '/' );
		if ( $home !== '/' && strpos( $path, $home ) === 0 ) {
			$path = substr( $path, strlen( $home ) ) ?: '/';
		}

		$blocked = false;
		$target  = '';
		if ( $hide_rest && preg_match( '#^/?wp-json(/|$)#', $path ) ) {
			$blocked = true;
			$target  = 'wp-json';
		} elseif ( $hide_xmlrpc && preg_match( '#^/?xmlrpc\.php($|\?)#', $path ) ) {
			$blocked = true;
			$target  = 'xmlrpc';
		}

		if ( ! $blocked ) {
			return;
		}

		DSM_Activity_Log::record( DSM_Activity_Log::EVT_HIDDEN_URL_SCAN, [
			'details' => [ 'target' => $target ],
		] );

		// Defer to the Hidden_Login engine's blocked-response renderer so the user
		// gets exactly the same look-and-feel as a /wp-admin probe.
		DSM_Plugin::instance()->hidden_login->respond_blocked( $target );
	}

	public static function is_api_request(): bool {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return true;
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return true;
		}
		// Catch the case where REST_REQUEST hasn't been set yet but the URL
		// matches the REST prefix. wp_authenticate can fire before rest_request.
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		if ( strpos( $uri, '/wp-json' ) !== false ) {
			return true;
		}
		return false;
	}

	private static function api_context_label(): string {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return 'xmlrpc';
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return 'rest';
		}
		return 'api';
	}
}
