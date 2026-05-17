<?php
/**
 * Deactivation hook: drops scheduled events; preserves data so a re-activate keeps history.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class DSM_Deactivator {
	public static function deactivate(): void {
		$timestamp = wp_next_scheduled( 'dsm_daily_cleanup' );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, 'dsm_daily_cleanup' );
		}
		flush_rewrite_rules();
	}
}
