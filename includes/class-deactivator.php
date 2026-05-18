<?php
/**
 * Deactivation hook: drops scheduled events; preserves data so a re-activate keeps history.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class DEFSEC_Deactivator {
	public static function deactivate(): void {
		$timestamp = wp_next_scheduled( 'defsec_daily_cleanup' );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, 'defsec_daily_cleanup' );
		}
		flush_rewrite_rules();
	}
}
