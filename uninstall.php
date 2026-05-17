<?php
/**
 * Fires when the user deletes the plugin via the WP Plugins screen.
 *
 * Cleans up plugin options, our two custom tables, and any per-user 2FA secrets.
 * Direct DB queries are intentional here — uninstall.php has no caching to
 * worry about (the plugin is being removed) and DROP TABLE for our custom
 * tables can't be done via a higher-level API.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

delete_option( 'dsm_settings' );
delete_option( 'dsm_db_version' );
delete_site_option( 'dsm_settings' );

$log_table  = $wpdb->prefix . 'dsm_log';
$lock_table = $wpdb->prefix . 'dsm_lockouts';

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Uninstall cleanup of plugin-owned custom tables and usermeta; the plugin is being removed so caching is moot and there is no higher-level API for DROP TABLE. Table identifiers are built from $wpdb->prefix + plugin-owned constants.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $log_table ) );
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $lock_table ) );
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE %s", 'dsm\_%' ) );
// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
