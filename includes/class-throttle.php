<?php
/**
 * Failed-login throttle and IP lockout.
 *
 * Counts failed authentications per IP within a rolling window; when the threshold
 * is reached, the IP is locked out for a configurable duration and the lockout is
 * logged so the alerts dispatcher can notify the admin.
 *
 * Tracking lives in the `dsm_lockouts` table — durable across requests and
 * survives object cache flushes.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class DSM_Throttle {

	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'dsm_lockouts';
	}

	public function boot(): void {
		// Priority 96: must run AFTER wp_authenticate_username_password (priority 20),
		// otherwise WP's standard auth handler reprocesses and overwrites our WP_Error
		// with its "username not registered" message — defeating the lockout UX.
		add_filter( 'authenticate', [ $this, 'block_locked_ip' ], 96, 3 );
		add_action( 'wp_login_failed', [ $this, 'record_failure' ], 10, 2 );
		add_action( 'wp_login', [ $this, 'clear_on_success' ], 10, 2 );
	}

	/**
	 * Refuse the auth attempt early if the IP is currently locked out.
	 */
	public function block_locked_ip( $user, $username, $password ) {
		if ( ! DSM_Options::get( 'throttle_enabled' ) ) {
			return $user;
		}
		if ( empty( $username ) && empty( $password ) ) {
			return $user; // not an actual login submission
		}

		$ip = dsm_client_ip();
		if ( dsm_ip_in_list( $ip, (array) DSM_Options::get( 'ip_allowlist', [] ) ) ) {
			return $user; // allowlisted IPs bypass throttling
		}

		if ( $this->is_locked_out( $ip ) ) {
			return new WP_Error(
				'dsm_locked',
				__( '<strong>Too many failed attempts.</strong> Try again later.', 'defyn-security-manager' )
			);
		}
		return $user;
	}

	public function record_failure( $username, $error = null ): void {
		if ( ! DSM_Options::get( 'throttle_enabled' ) ) {
			return;
		}
		$ip = dsm_client_ip();
		if ( dsm_ip_in_list( $ip, (array) DSM_Options::get( 'ip_allowlist', [] ) ) ) {
			DSM_Activity_Log::record( DSM_Activity_Log::EVT_LOGIN_FAILED, [
				'ip' => $ip, 'username' => $username, 'details' => [ 'allowlisted' => true ],
			] );
			return;
		}

		self::increment_for_ip( $ip, $username );
	}

	/**
	 * Public entry point: register a single auth failure for an IP. Used by both
	 * the password failure hook and the 2FA failure path — share the same counter
	 * so an attacker can't sidestep the lockout by mixing password + 2FA tries.
	 *
	 * No-op if throttling is disabled or the IP is allowlisted (caller does the
	 * activity log entry in those cases since the failure category differs).
	 */
	public static function increment_for_ip( string $ip, string $username = '', bool $record_password_failure = true ): void {
		$max     = (int) DSM_Options::get( 'throttle_max_attempts' );
		$window  = (int) DSM_Options::get( 'throttle_window_min' ) * MINUTE_IN_SECONDS;
		$lockout = (int) DSM_Options::get( 'throttle_lockout_min' ) * MINUTE_IN_SECONDS;

		global $wpdb;
		$now_mysql = current_time( 'mysql', true );
		$table     = self::table();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Auth-time lookup against custom plugin table; not cacheable.
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM %i WHERE ip = %s', $table, $ip ), ARRAY_A );

		if ( ! $row ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- New lockout row in custom plugin table.
			$wpdb->insert( $table, [
				'ip'           => $ip,
				'attempts'     => 1,
				'first_seen'   => $now_mysql,
				'last_attempt' => $now_mysql,
			] );
			$attempts = 1;
		} else {
			$first_seen_ts = strtotime( $row['first_seen'] . ' UTC' );
			if ( time() - $first_seen_ts > $window ) {
				// Window expired — reset the counter.
				$attempts = 1;
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Reset counter on custom plugin table.
				$wpdb->update( $table, [
					'attempts'     => 1,
					'first_seen'   => $now_mysql,
					'last_attempt' => $now_mysql,
					'locked_until' => null,
				], [ 'id' => $row['id'] ] );
			} else {
				$attempts = (int) $row['attempts'] + 1;
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Increment counter on custom plugin table.
				$wpdb->update( $table, [
					'attempts'     => $attempts,
					'last_attempt' => $now_mysql,
				], [ 'id' => $row['id'] ] );
			}
		}

		// The 2FA path records `2fa_failed` separately, so we only write a
		// `login_failed` entry for the password path.
		if ( $record_password_failure ) {
			DSM_Activity_Log::record( DSM_Activity_Log::EVT_LOGIN_FAILED, [
				'ip'       => $ip,
				'username' => $username,
				'details'  => [ 'attempts' => $attempts, 'max' => $max ],
			] );
		}

		if ( $attempts >= $max ) {
			$locked_until = gmdate( 'Y-m-d H:i:s', time() + $lockout );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Set lockout timestamp on custom plugin table.
			$wpdb->update( $table,
				[ 'locked_until' => $locked_until ],
				[ 'ip' => $ip ]
			);
			DSM_Activity_Log::record( DSM_Activity_Log::EVT_LOCKOUT, [
				'ip'       => $ip,
				'username' => $username,
				'details'  => [ 'locked_until' => $locked_until, 'attempts' => $attempts ],
			] );
		}
	}

	public function clear_on_success( $user_login, $user ): void {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Clear successful-login user's lockout counter from custom plugin table.
		$wpdb->delete( self::table(), [ 'ip' => dsm_client_ip() ] );
	}

	/**
	 * How many IPs are currently in a lockout state (used by the admin UI to
	 * decide whether to show the "Clear all lockouts" button).
	 */
	public static function count_active(): int {
		global $wpdb;
		$now = current_time( 'mysql', true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Live count on custom plugin table; UI must reflect current state.
		return (int) $wpdb->get_var( $wpdb->prepare(
			'SELECT COUNT(*) FROM %i WHERE locked_until IS NOT NULL AND locked_until > %s',
			self::table(),
			$now
		) );
	}

	public function is_locked_out( string $ip ): bool {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Auth-time gate must read fresh state from custom plugin table.
		$locked_until = $wpdb->get_var( $wpdb->prepare(
			'SELECT locked_until FROM %i WHERE ip = %s',
			self::table(),
			$ip
		) );
		if ( ! $locked_until ) {
			return false;
		}
		return strtotime( $locked_until . ' UTC' ) > time();
	}

	/**
	 * Drop expired lockout rows. Called from cron.
	 */
	public static function prune(): int {
		global $wpdb;
		$now = current_time( 'mysql', true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Daily cron pruning of custom plugin table.
		return (int) $wpdb->query( $wpdb->prepare(
			'DELETE FROM %i WHERE locked_until IS NOT NULL AND locked_until < %s',
			self::table(),
			$now
		) );
	}
}
