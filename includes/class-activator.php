<?php
/**
 * Activation hook: provisions DB tables, seeds defaults, schedules cron.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class DSM_Activator {

	const DB_VERSION = '1';

	public static function activate(): void {
		self::install_tables();

		$existing = get_option( DSM_OPTION );
		if ( ! is_array( $existing ) || empty( $existing ) ) {
			$defaults = DSM_Options::defaults();
			// First install: randomize the slug so the URL isn't predictable.
			$defaults['login_slug'] = 'be-' . dsm_random_slug( 10 );
			$defaults['alerts_email'] = get_option( 'admin_email' );
			update_option( DSM_OPTION, $defaults );
		}

		if ( ! wp_next_scheduled( 'dsm_daily_cleanup' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'dsm_daily_cleanup' );
		}

		flush_rewrite_rules();
	}

	private static function install_tables(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$log     = $wpdb->prefix . 'dsm_log';
		$lock    = $wpdb->prefix . 'dsm_lockouts';

		$sql_log = "CREATE TABLE $log (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			created_at DATETIME NOT NULL,
			event_type VARCHAR(40) NOT NULL,
			ip VARCHAR(45) NOT NULL DEFAULT '',
			username VARCHAR(190) NOT NULL DEFAULT '',
			user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
			user_agent VARCHAR(255) NOT NULL DEFAULT '',
			request_uri VARCHAR(255) NOT NULL DEFAULT '',
			details LONGTEXT NULL,
			PRIMARY KEY  (id),
			KEY event_type (event_type),
			KEY ip (ip),
			KEY created_at (created_at)
		) $charset;";

		$sql_lock = "CREATE TABLE $lock (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			ip VARCHAR(45) NOT NULL,
			attempts INT UNSIGNED NOT NULL DEFAULT 0,
			first_seen DATETIME NOT NULL,
			last_attempt DATETIME NOT NULL,
			locked_until DATETIME NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY ip (ip),
			KEY locked_until (locked_until)
		) $charset;";

		dbDelta( $sql_log );
		dbDelta( $sql_lock );

		update_option( 'dsm_db_version', self::DB_VERSION );
	}
}
