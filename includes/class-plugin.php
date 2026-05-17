<?php
/**
 * Main plugin orchestrator.
 *
 * Composes the feature classes and wires them to the WP lifecycle.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class DSM_Plugin {

	private static ?self $instance = null;

	public DSM_Hidden_Login $hidden_login;
	public DSM_Throttle     $throttle;
	public DSM_Time_Window  $time_window;
	public DSM_Two_Factor   $two_factor;
	public DSM_API_Guard    $api_guard;
	public DSM_Email_Alerts $alerts;
	public DSM_Admin        $admin;

	public static function instance(): self {
		if ( ! self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->hidden_login = new DSM_Hidden_Login();
		$this->throttle     = new DSM_Throttle();
		$this->time_window  = new DSM_Time_Window();
		$this->two_factor   = new DSM_Two_Factor();
		$this->api_guard    = new DSM_API_Guard();
		$this->alerts       = new DSM_Email_Alerts();
		$this->admin        = new DSM_Admin();
	}

	public function boot(): void {
		// Translation loading is handled automatically by WordPress.org since WP 4.6;
		// no explicit load_plugin_textdomain() call required for plugins hosted on
		// the WordPress.org plugin directory.

		$disabled = self::is_disabled();

		if ( ! $disabled ) {
			// Core hide-the-backend behavior must boot before everything else.
			$this->hidden_login->boot();

			// Authentication-time guards. Filter priority order on `authenticate`:
			//   95 time_window → 96 throttle → 97 api_guard → 100 two_factor (browser flow)
			// All of these run AFTER WP's wp_authenticate_username_password at priority 20
			// so they receive a fully-resolved WP_User (or WP_Error) and can override.
			$this->time_window->boot();
			$this->throttle->boot();
			$this->api_guard->boot();
			$this->two_factor->boot();
		}

		// Logging side-effects — kept on in disable mode so we still capture audit
		// trail of any logins that happen while the kill switch is active.
		$this->alerts->boot();
		add_action( 'wp_login', [ $this, 'on_login_success' ], 5, 2 );

		// Admin UI — critical in disable mode too, since that's how the user
		// fixes whatever locked them out.
		if ( is_admin() ) {
			$this->admin->boot();
			if ( $disabled ) {
				add_action( 'admin_notices', [ $this, 'render_disabled_notice' ] );
				$this->log_disabled_mode_once();
			}
		}

		// Daily housekeeping cron — prune activity log + expired lockout rows.
		add_action( 'dsm_daily_cleanup', [ $this, 'run_daily_cleanup' ] );
	}

	/**
	 * Emergency kill switch. When `DSM_DISABLE` is defined and truthy in
	 * wp-config.php, the plugin skips all auth-interception so /wp-admin and
	 * /wp-login.php behave like a vanilla WordPress install. Admin UI, activity
	 * log, alerts, and updates stay on so the operator can fix the cause and
	 * remove the constant.
	 */
	public static function is_disabled(): bool {
		return defined( 'DSM_DISABLE' ) && DSM_DISABLE;
	}

	public function render_disabled_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		echo '<div class="notice notice-warning"><p>'
			. wp_kses_post( __( '<strong>Defyn Security Manager kill switch is active.</strong> All security guards (hidden URL, throttle, time window, 2FA) are bypassed because <code>DSM_DISABLE</code> is defined in <code>wp-config.php</code>. Remove that line from <code>wp-config.php</code> once you have finished recovery.', 'defyn-security-manager' ) )
			. '</p></div>';
	}

	/**
	 * Record the disable event in the activity log at most once per hour, so an
	 * incident response timeline can show when the kill switch was used without
	 * flooding the log on every admin page hit.
	 */
	private function log_disabled_mode_once(): void {
		$marker = 'dsm_disable_logged_at';
		$last   = (int) get_transient( $marker );
		if ( time() - $last < HOUR_IN_SECONDS ) {
			return;
		}
		set_transient( $marker, time(), HOUR_IN_SECONDS );
		DSM_Activity_Log::record( DSM_Activity_Log::EVT_SETTINGS_CHANGED, [
			'user_id' => get_current_user_id(),
			'details' => [ 'kill_switch' => 'DSM_DISABLE active' ],
		] );
	}

	public function on_login_success( string $user_login, WP_User $user ): void {
		$ip      = dsm_client_ip();
		$new_ip  = ! DSM_Activity_Log::user_has_logged_in_from_ip( $user->ID, $ip );

		DSM_Activity_Log::record( DSM_Activity_Log::EVT_LOGIN_SUCCESS, [
			'ip'       => $ip,
			'username' => $user_login,
			'user_id'  => $user->ID,
			'details'  => [ 'new_ip' => $new_ip ],
		] );
	}

	public function run_daily_cleanup(): void {
		DSM_Activity_Log::prune();
		DSM_Throttle::prune();
	}
}
