<?php
/**
 * Admin layer: top-level menu, settings page (tabbed), activity log page.
 *
 * Settings are saved via the WP Settings API (`register_setting`), sanitized
 * through DSM_Options::sanitize, and split across tabs for navigability.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class DSM_Admin {

	public function boot(): void {
		add_action( 'admin_menu', [ $this, 'register_menu' ] );
		add_action( 'admin_init', [ $this, 'register_settings' ] );
		add_action( 'admin_init', [ $this, 'handle_clear_lockouts' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_assets' ] );

		add_filter( 'plugin_action_links_' . DSM_BASENAME, [ $this, 'plugin_action_links' ] );

		// Audit settings updates so admins can spot policy changes in the activity log.
		add_action( 'update_option_' . DSM_OPTION, [ $this, 'on_settings_update' ], 10, 2 );
	}

	public function register_menu(): void {
		$cap  = 'manage_options';
		$icon = 'dashicons-shield-alt';
		$pos  = 80;

		add_menu_page(
			__( 'Defyn Security Manager', 'defyn-security-manager' ),
			__( 'BE Security', 'defyn-security-manager' ),
			$cap,
			DSM_SLUG,
			[ $this, 'render_settings_page' ],
			$icon,
			$pos
		);

		add_submenu_page(
			DSM_SLUG,
			__( 'Settings', 'defyn-security-manager' ),
			__( 'Settings', 'defyn-security-manager' ),
			$cap,
			DSM_SLUG,
			[ $this, 'render_settings_page' ]
		);
		add_submenu_page(
			DSM_SLUG,
			__( 'Activity Log', 'defyn-security-manager' ),
			__( 'Activity Log', 'defyn-security-manager' ),
			$cap,
			DSM_SLUG . '-log',
			[ $this, 'render_log_page' ]
		);
	}

	public function register_settings(): void {
		register_setting(
			'dsm_settings_group',
			DSM_OPTION,
			[
				'sanitize_callback' => [ DSM_Options::class, 'sanitize' ],
				'default'           => DSM_Options::defaults(),
			]
		);
	}

	public function enqueue_assets( string $hook ): void {
		if ( strpos( $hook, DSM_SLUG ) === false ) {
			return;
		}
		wp_enqueue_style(
			'besm-admin',
			DSM_URL . 'assets/css/admin.css',
			[],
			DSM_VERSION
		);
	}

	public function plugin_action_links( array $links ): array {
		$settings_url = admin_url( 'admin.php?page=' . DSM_SLUG );
		array_unshift( $links, '<a href="' . esc_url( $settings_url ) . '">' . esc_html__( 'Settings', 'defyn-security-manager' ) . '</a>' );
		return $links;
	}

	public function on_settings_update( $old, $new ): void {
		$diff = [];
		foreach ( (array) $new as $k => $v ) {
			if ( ! isset( $old[ $k ] ) || $old[ $k ] !== $v ) {
				// Don't log the hashed bypass code value.
				$diff[] = $k === 'emergency_bypass_code' ? $k . ':<changed>' : $k;
			}
		}
		if ( $diff ) {
			DSM_Activity_Log::record( DSM_Activity_Log::EVT_SETTINGS_CHANGED, [
				'user_id' => get_current_user_id(),
				'details' => [ 'changed' => $diff ],
			] );
		}
	}

	public function handle_clear_lockouts(): void {
		if ( empty( $_POST['dsm_clear_lockouts'] ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		check_admin_referer( 'dsm_clear_lockouts' );

		global $wpdb;
		$table = DSM_Throttle::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Admin-triggered clear of custom plugin table.
		$cleared = (int) $wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $table ) );

		DSM_Activity_Log::record( DSM_Activity_Log::EVT_SETTINGS_CHANGED, [
			'user_id' => get_current_user_id(),
			'details' => [ 'action' => 'clear_lockouts', 'cleared' => $cleared ],
		] );

		$message = sprintf(
			/* translators: %d: number of cleared rows */
			_n( 'Cleared %d active lockout.', 'Cleared %d active lockouts.', $cleared, 'defyn-security-manager' ),
			$cleared
		);
		set_transient( 'dsm_settings_notice', [
			'ok'      => true,
			'message' => $message,
		], 30 );

		wp_safe_redirect( add_query_arg( 'tab', 'security', admin_url( 'admin.php?page=' . DSM_SLUG ) ) );
		exit;
	}

	public function render_settings_page(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only tab selector for admin settings page; no state mutation.
		$active_tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'general';
		$tabs = [
			'general'  => __( 'Hidden URL', 'defyn-security-manager' ),
			'security' => __( 'Security', 'defyn-security-manager' ),
			'2fa'      => __( 'Two-Factor', 'defyn-security-manager' ),
			'alerts'   => __( 'Alerts & Logging', 'defyn-security-manager' ),
		];
		$settings = DSM_Options::all();
		include DSM_PATH . 'admin/views/settings.php';
	}

	public function render_log_page(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only admin log viewer; query params are pagination + filter selectors, all sanitized below. No state mutation.
		$page     = max( 1, isset( $_GET['paged'] ) ? (int) $_GET['paged'] : 1 );
		$per_page = 25;
		$filters  = [
			'event_type' => isset( $_GET['event'] ) ? sanitize_key( wp_unslash( $_GET['event'] ) ) : '',
			'ip'         => isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : '',
			'limit'      => $per_page,
			'offset'     => ( $page - 1 ) * $per_page,
		];
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		$rows  = DSM_Activity_Log::query( $filters );
		$total = DSM_Activity_Log::count( $filters );
		include DSM_PATH . 'admin/views/activity-log.php';
	}
}
