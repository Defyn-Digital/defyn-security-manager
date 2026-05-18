<?php
/**
 * Strongly-typed accessor for plugin settings.
 *
 * Keeps default values in one place and sanitizes on save.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class DEFSEC_Options {

	public static function defaults(): array {
		return [
			'login_slug'             => 'defyn-login',
			'blocked_response'       => '404', // 404 | redirect | fake
			'blocked_redirect_url'   => '',

			'throttle_enabled'       => true,
			'throttle_max_attempts'  => 5,
			'throttle_window_min'    => 15,
			'throttle_lockout_min'   => 30,

			'ip_allowlist'           => [], // array of IPs / CIDR

			'time_window_enabled'    => false,
			'time_window_start'      => '08:00',
			'time_window_end'        => '20:00',
			'time_window_days'       => [ 1, 2, 3, 4, 5 ], // 0=Sun
			'emergency_bypass_code'  => '', // hashed

			'two_factor_enabled'     => false,
			'two_factor_required_roles' => [ 'administrator' ],

			'hide_rest_api'          => false,
			'hide_xmlrpc'            => false,

			'alerts_enabled'         => true,
			'alerts_email'           => '',
			'alerts_on_lockout'      => true,
			'alerts_on_scan'         => false,
			'alerts_on_new_ip_login' => true,

			'log_retention_days'     => 30,
		];
	}

	public static function all(): array {
		$stored = get_option( DEFSEC_OPTION, [] );
		if ( ! is_array( $stored ) ) {
			$stored = [];
		}
		return array_merge( self::defaults(), $stored );
	}

	public static function get( string $key, $fallback = null ) {
		$all = self::all();
		return array_key_exists( $key, $all ) ? $all[ $key ] : $fallback;
	}

	public static function update( array $partial ): bool {
		$current = self::all();
		$merged  = array_merge( $current, self::sanitize( $partial ) );
		return update_option( DEFSEC_OPTION, $merged );
	}

	public static function replace( array $values ): bool {
		return update_option( DEFSEC_OPTION, self::sanitize( $values ) );
	}

	/**
	 * Sanitize a partial or complete settings array.
	 */
	public static function sanitize( array $input ): array {
		$out = [];

		if ( isset( $input['login_slug'] ) ) {
			$slug = defsec_sanitize_slug( (string) $input['login_slug'] );
			if ( strlen( $slug ) >= 4 ) {
				$out['login_slug'] = $slug;
			}
		}
		if ( isset( $input['blocked_response'] ) ) {
			$out['blocked_response'] = in_array( $input['blocked_response'], [ '404', 'redirect', 'fake' ], true )
				? $input['blocked_response']
				: '404';
		}
		if ( isset( $input['blocked_redirect_url'] ) ) {
			$out['blocked_redirect_url'] = esc_url_raw( (string) $input['blocked_redirect_url'] );
		}

		if ( isset( $input['throttle_enabled'] ) ) {
			$out['throttle_enabled'] = (bool) $input['throttle_enabled'];
		}
		if ( isset( $input['throttle_max_attempts'] ) ) {
			$out['throttle_max_attempts'] = max( 1, min( 50, (int) $input['throttle_max_attempts'] ) );
		}
		if ( isset( $input['throttle_window_min'] ) ) {
			$out['throttle_window_min'] = max( 1, min( 1440, (int) $input['throttle_window_min'] ) );
		}
		if ( isset( $input['throttle_lockout_min'] ) ) {
			$out['throttle_lockout_min'] = max( 1, min( 10080, (int) $input['throttle_lockout_min'] ) );
		}

		if ( isset( $input['ip_allowlist'] ) ) {
			$raw = is_array( $input['ip_allowlist'] )
				? $input['ip_allowlist']
				: preg_split( '/[\r\n,]+/', (string) $input['ip_allowlist'] );
			$out['ip_allowlist'] = array_values( array_filter( array_map( 'trim', $raw ) ) );
		}

		if ( isset( $input['time_window_enabled'] ) ) {
			$out['time_window_enabled'] = (bool) $input['time_window_enabled'];
		}
		foreach ( [ 'time_window_start', 'time_window_end' ] as $k ) {
			if ( isset( $input[ $k ] ) && preg_match( '/^([01]\d|2[0-3]):[0-5]\d$/', (string) $input[ $k ] ) ) {
				$out[ $k ] = $input[ $k ];
			}
		}
		if ( isset( $input['time_window_days'] ) ) {
			$days = is_array( $input['time_window_days'] ) ? $input['time_window_days'] : [];
			$out['time_window_days'] = array_values( array_unique( array_filter(
				array_map( 'intval', $days ),
				static fn( $d ) => $d >= 0 && $d <= 6
			) ) );
		}
		if ( isset( $input['emergency_bypass_code'] ) && $input['emergency_bypass_code'] !== '' ) {
			// Store as hash so a settings export doesn't leak the code.
			$code = (string) $input['emergency_bypass_code'];
			if ( strlen( $code ) >= 8 ) {
				$out['emergency_bypass_code'] = wp_hash_password( $code );
			}
		}

		if ( isset( $input['two_factor_enabled'] ) ) {
			$out['two_factor_enabled'] = (bool) $input['two_factor_enabled'];
		}
		if ( isset( $input['two_factor_required_roles'] ) ) {
			$roles = is_array( $input['two_factor_required_roles'] ) ? $input['two_factor_required_roles'] : [];
			$valid = array_keys( wp_roles()->roles );
			$out['two_factor_required_roles'] = array_values( array_intersect( $roles, $valid ) );
		}

		foreach ( [ 'hide_rest_api', 'hide_xmlrpc' ] as $k ) {
			if ( isset( $input[ $k ] ) ) {
				$out[ $k ] = (bool) $input[ $k ];
			}
		}

		if ( isset( $input['alerts_enabled'] ) ) {
			$out['alerts_enabled'] = (bool) $input['alerts_enabled'];
		}
		if ( isset( $input['alerts_email'] ) ) {
			$email = sanitize_email( (string) $input['alerts_email'] );
			$out['alerts_email'] = is_email( $email ) ? $email : '';
		}
		foreach ( [ 'alerts_on_lockout', 'alerts_on_scan', 'alerts_on_new_ip_login' ] as $k ) {
			if ( isset( $input[ $k ] ) ) {
				$out[ $k ] = (bool) $input[ $k ];
			}
		}

		if ( isset( $input['log_retention_days'] ) ) {
			$out['log_retention_days'] = max( 1, min( 365, (int) $input['log_retention_days'] ) );
		}

		return $out;
	}
}
