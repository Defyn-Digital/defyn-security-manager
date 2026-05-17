<?php
/**
 * Append-only event log persisted in a custom table.
 *
 * Keeps event_type machine-readable so the UI can filter and the alerts dispatcher
 * can subscribe to specific events.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class DSM_Activity_Log {

	const EVT_LOGIN_SUCCESS    = 'login_success';
	const EVT_LOGIN_FAILED     = 'login_failed';
	const EVT_LOCKOUT          = 'lockout';
	const EVT_HIDDEN_URL_SCAN  = 'hidden_url_scan';
	const EVT_TIME_WINDOW_DENY = 'time_window_deny';
	const EVT_2FA_FAILED       = '2fa_failed';
	const EVT_2FA_SUCCESS      = '2fa_success';
	const EVT_2FA_ENROLLED     = '2fa_enrolled';
	const EVT_2FA_DISABLED     = '2fa_disabled';
	const EVT_SETTINGS_CHANGED = 'settings_changed';

	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'dsm_log';
	}

	/**
	 * Record an event. `$details` is JSON-encoded.
	 */
	public static function record( string $event_type, array $context = [] ): int {
		global $wpdb;

		$row = [
			'created_at'  => current_time( 'mysql', true ),
			'event_type'  => substr( $event_type, 0, 40 ),
			'ip'          => $context['ip'] ?? dsm_client_ip(),
			'username'    => substr( (string) ( $context['username'] ?? '' ), 0, 190 ),
			'user_id'     => (int) ( $context['user_id'] ?? 0 ),
			'user_agent'  => substr( isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '', 0, 255 ),
			'request_uri' => substr( isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '', 0, 255 ),
			'details'     => $context['details'] ?? null,
		];

		if ( is_array( $row['details'] ) ) {
			$row['details'] = wp_json_encode( $row['details'] );
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Audit log insert into a custom plugin table; not cacheable.
		$wpdb->insert( self::table(), $row );
		$id = (int) $wpdb->insert_id;

		do_action( 'dsm_event_recorded', $event_type, $row, $id );

		return $id;
	}

	/**
	 * Fetch events with optional filters. Used by the admin dashboard.
	 */
	public static function query( array $args = [] ): array {
		global $wpdb;

		$args = wp_parse_args( $args, [
			'event_type' => '',
			'ip'         => '',
			'username'   => '',
			'limit'      => 50,
			'offset'     => 0,
		] );

		$where  = [ '1=1' ];
		$params = [ self::table() ]; // %i — table name placeholder.
		if ( $args['event_type'] !== '' ) {
			$where[]  = 'event_type = %s';
			$params[] = $args['event_type'];
		}
		if ( $args['ip'] !== '' ) {
			$where[]  = 'ip = %s';
			$params[] = $args['ip'];
		}
		if ( $args['username'] !== '' ) {
			$where[]  = 'username LIKE %s';
			$params[] = '%' . $wpdb->esc_like( $args['username'] ) . '%';
		}
		$params[] = (int) $args['limit'];
		$params[] = (int) $args['offset'];

		$sql = 'SELECT * FROM %i WHERE ' . implode( ' AND ', $where )
		     . ' ORDER BY created_at DESC LIMIT %d OFFSET %d';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $sql is composed only of static string fragments plus %i/%s/%d placeholders; passed through $wpdb->prepare() with $params.
		return $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A ) ?: [];
	}

	public static function count( array $args = [] ): int {
		global $wpdb;
		$args = wp_parse_args( $args, [ 'event_type' => '', 'ip' => '' ] );

		$where  = [ '1=1' ];
		$params = [ self::table() ];
		if ( $args['event_type'] !== '' ) {
			$where[]  = 'event_type = %s';
			$params[] = $args['event_type'];
		}
		if ( $args['ip'] !== '' ) {
			$where[]  = 'ip = %s';
			$params[] = $args['ip'];
		}

		$sql = 'SELECT COUNT(*) FROM %i WHERE ' . implode( ' AND ', $where );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $sql is composed only of static string fragments plus %i/%s placeholders; passed through $wpdb->prepare() with $params.
		return (int) $wpdb->get_var( $wpdb->prepare( $sql, $params ) );
	}

	/**
	 * Drop rows older than the configured retention. Called from the daily cron.
	 */
	public static function prune(): int {
		global $wpdb;
		$days = (int) DSM_Options::get( 'log_retention_days', 30 );
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Cron pruning of custom plugin table.
		return (int) $wpdb->query( $wpdb->prepare(
			'DELETE FROM %i WHERE created_at < %s',
			self::table(),
			$cutoff
		) );
	}

	/**
	 * Has this user successfully logged in from this IP before?
	 * Used by the "new IP login" alert.
	 */
	public static function user_has_logged_in_from_ip( int $user_id, string $ip ): bool {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table; auth-flow query, intentionally uncached for freshness.
		$row = $wpdb->get_var( $wpdb->prepare(
			'SELECT id FROM %i WHERE event_type = %s AND user_id = %d AND ip = %s LIMIT 1',
			self::table(),
			self::EVT_LOGIN_SUCCESS,
			$user_id,
			$ip
		) );
		return ! empty( $row );
	}
}
