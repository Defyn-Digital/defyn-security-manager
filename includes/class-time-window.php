<?php
/**
 * Time-window access control.
 *
 * When enabled, login attempts outside the configured days/hours are rejected.
 * The admin can set an emergency bypass code that, when supplied via a
 * `?defyn_bypass=<code>` query param, lets a single attempt through.
 *
 * The hidden URL itself stays reachable outside the window — only the actual
 * auth attempt is blocked. That avoids self-lockout scenarios where the admin
 * mistypes the clock and the entire backend disappears.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class DEFSEC_Time_Window {

	public function boot(): void {
		// Priority 95: must run AFTER wp_authenticate_username_password (priority 20),
		// otherwise WP's standard auth handler reprocesses and overwrites our WP_Error.
		// Sits just before the throttle (96) so a lockout takes precedence in the
		// double-failure case (locked out AND outside time window — show lockout).
		add_filter( 'authenticate', [ $this, 'guard' ], 95, 3 );
	}

	public function guard( $user, $username, $password ) {
		if ( ! DEFSEC_Options::get( 'time_window_enabled' ) ) {
			return $user;
		}
		if ( empty( $username ) && empty( $password ) ) {
			return $user;
		}
		if ( $this->bypass_supplied() ) {
			return $user;
		}
		if ( $this->is_within_window() ) {
			return $user;
		}

		DEFSEC_Activity_Log::record( DEFSEC_Activity_Log::EVT_TIME_WINDOW_DENY, [
			'username' => $username,
		] );

		return new WP_Error(
			'defsec_time_window',
			__( '<strong>Login disabled.</strong> Backend access is restricted at this time.', 'defyn-security-manager' )
		);
	}

	private function is_within_window(): bool {
		$tz   = defsec_site_timezone();
		$now  = new DateTime( 'now', $tz );
		$day  = (int) $now->format( 'w' );  // 0=Sun..6=Sat
		$days = (array) DEFSEC_Options::get( 'time_window_days', [] );
		if ( ! in_array( $day, array_map( 'intval', $days ), true ) ) {
			return false;
		}

		$start_str = (string) DEFSEC_Options::get( 'time_window_start', '08:00' );
		$end_str   = (string) DEFSEC_Options::get( 'time_window_end', '20:00' );

		$today = $now->format( 'Y-m-d' );
		$start = DateTime::createFromFormat( 'Y-m-d H:i', "$today $start_str", $tz );
		$end   = DateTime::createFromFormat( 'Y-m-d H:i', "$today $end_str", $tz );

		if ( ! $start || ! $end ) {
			return true;
		}

		// Handle windows that cross midnight (e.g. 22:00–06:00).
		if ( $end <= $start ) {
			return $now >= $start || $now <= $end;
		}
		return $now >= $start && $now <= $end;
	}

	private function bypass_supplied(): bool {
		$stored = (string) DEFSEC_Options::get( 'emergency_bypass_code', '' );
		if ( $stored === '' ) {
			return false;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- The bypass code is itself the per-request secret; checked with wp_check_password() below.
		$supplied = isset( $_REQUEST['defyn_bypass'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['defyn_bypass'] ) ) : '';
		if ( $supplied === '' ) {
			return false;
		}
		return wp_check_password( $supplied, $stored );
	}
}
