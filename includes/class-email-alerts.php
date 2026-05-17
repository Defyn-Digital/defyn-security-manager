<?php
/**
 * Email alerts dispatcher.
 *
 * Subscribes to the activity log and sends mail for the events the admin opts into.
 * Light rate limiting prevents an attacker from flooding the admin's inbox by
 * hammering the login form.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class DSM_Email_Alerts {

	const RATE_LIMIT_KEY     = 'dsm_alert_window';
	const RATE_LIMIT_WINDOW  = 600;  // 10 minutes
	const RATE_LIMIT_MAX     = 10;   // max alerts per window

	public function boot(): void {
		add_action( 'dsm_event_recorded', [ $this, 'on_event' ], 10, 3 );
	}

	public function on_event( string $event, array $row, int $id ): void {
		if ( ! DSM_Options::get( 'alerts_enabled' ) ) {
			return;
		}
		$to = DSM_Options::get( 'alerts_email' );
		if ( ! is_email( $to ) ) {
			return;
		}

		$send = false;
		$subject = '';
		$body    = '';

		switch ( $event ) {
			case DSM_Activity_Log::EVT_LOCKOUT:
				if ( DSM_Options::get( 'alerts_on_lockout' ) ) {
					$send    = true;
					$subject = sprintf( '[%s] IP locked out: %s', $this->site_name(), $row['ip'] );
					$body    = "An IP has been locked out after repeated failed login attempts.\n\n"
						. "IP: {$row['ip']}\nUsername tried: {$row['username']}\nUser-Agent: {$row['user_agent']}\nTime (UTC): {$row['created_at']}\n";
				}
				break;
			case DSM_Activity_Log::EVT_HIDDEN_URL_SCAN:
				if ( DSM_Options::get( 'alerts_on_scan' ) ) {
					$send    = true;
					$subject = sprintf( '[%s] Someone hit the original /wp-admin', $this->site_name() );
					$body    = "Someone requested a hidden WordPress login URL.\n\n"
						. "IP: {$row['ip']}\nRequest: {$row['request_uri']}\nUser-Agent: {$row['user_agent']}\nTime (UTC): {$row['created_at']}\n";
				}
				break;
			case DSM_Activity_Log::EVT_LOGIN_SUCCESS:
				if ( ! DSM_Options::get( 'alerts_on_new_ip_login' ) ) {
					break;
				}
				$details = is_string( $row['details'] ) ? json_decode( $row['details'], true ) : [];
				if ( empty( $details['new_ip'] ) ) {
					break;
				}
				$send    = true;
				$subject = sprintf( '[%s] Login from new IP: %s', $this->site_name(), $row['username'] );
				$body    = "A user successfully logged in from an IP not seen before.\n\n"
					. "User: {$row['username']}\nIP: {$row['ip']}\nUser-Agent: {$row['user_agent']}\nTime (UTC): {$row['created_at']}\n";
				break;
		}

		if ( ! $send || ! $this->within_rate_limit() ) {
			return;
		}

		wp_mail( $to, $subject, $body );
	}

	private function within_rate_limit(): bool {
		$state = get_transient( self::RATE_LIMIT_KEY );
		if ( ! is_array( $state ) ) {
			$state = [ 'count' => 0, 'window_start' => time() ];
		}
		if ( time() - $state['window_start'] > self::RATE_LIMIT_WINDOW ) {
			$state = [ 'count' => 0, 'window_start' => time() ];
		}
		if ( $state['count'] >= self::RATE_LIMIT_MAX ) {
			return false;
		}
		$state['count']++;
		set_transient( self::RATE_LIMIT_KEY, $state, self::RATE_LIMIT_WINDOW );
		return true;
	}

	private function site_name(): string {
		return wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
	}
}
