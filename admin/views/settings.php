<?php
/**
 * Settings page renderer. Variables in scope: $active_tab, $tabs, $settings.
 *
 * phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
 * -- This file is `include`d from DEFSEC_Admin::render_settings_page(), so every
 * variable declared here is method-scoped, not truly global. PHPCS's static
 * analysis can't see the include context.
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }

$current_login_url = home_url( '/' . $settings['login_slug'] );
$roles_all         = wp_roles()->roles;
$days              = [
	0 => __( 'Sun', 'defyn-security-manager' ),
	1 => __( 'Mon', 'defyn-security-manager' ),
	2 => __( 'Tue', 'defyn-security-manager' ),
	3 => __( 'Wed', 'defyn-security-manager' ),
	4 => __( 'Thu', 'defyn-security-manager' ),
	5 => __( 'Fri', 'defyn-security-manager' ),
	6 => __( 'Sat', 'defyn-security-manager' ),
];
$selected_days = array_map( 'intval', (array) $settings['time_window_days'] );
?>
<?php
$notice = get_transient( 'defsec_settings_notice' );
if ( $notice ) {
	delete_transient( 'defsec_settings_notice' );
}
?>
<div class="wrap defyn-bem-wrap">
	<h1><?php esc_html_e( 'Defyn Security Manager', 'defyn-security-manager' ); ?></h1>

	<?php if ( is_array( $notice ) ) :
		$cls = ! empty( $notice['ok'] ) ? 'notice-success' : 'notice-error'; ?>
		<div class="notice <?php echo esc_attr( $cls ); ?> is-dismissible">
			<p><?php echo esc_html( $notice['message'] ?? '' ); ?></p>
		</div>
	<?php endif; ?>

	<h2 class="nav-tab-wrapper">
		<?php foreach ( $tabs as $key => $label ) :
			$url = admin_url( 'admin.php?page=' . DEFSEC_SLUG . '&tab=' . $key );
			$cls = 'nav-tab' . ( $active_tab === $key ? ' nav-tab-active' : '' );
			?>
			<a href="<?php echo esc_url( $url ); ?>" class="<?php echo esc_attr( $cls ); ?>"><?php echo esc_html( $label ); ?></a>
		<?php endforeach; ?>
	</h2>

	<form method="post" action="options.php" class="defyn-bem-form">
		<?php settings_fields( 'defsec_settings_group' ); ?>

		<?php if ( $active_tab === 'general' ) : ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="login_slug"><?php esc_html_e( 'Hidden login slug', 'defyn-security-manager' ); ?></label></th>
					<td>
						<code><?php echo esc_html( trailingslashit( home_url( '/' ) ) ); ?></code>
						<input type="text" id="login_slug" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[login_slug]"
						       value="<?php echo esc_attr( $settings['login_slug'] ); ?>" class="regular-text" />
						<p class="description">
							<?php esc_html_e( 'Lowercase letters, numbers, and hyphens. Minimum 4 characters.', 'defyn-security-manager' ); ?>
							<?php
							echo wp_kses_post( sprintf(
								/* translators: %s: current full URL */
								__( 'Current URL: <code>%s</code>', 'defyn-security-manager' ),
								esc_url( $current_login_url )
							) );
							?>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'When someone visits /wp-admin or /wp-login', 'defyn-security-manager' ); ?></th>
					<td>
						<label><input type="radio" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[blocked_response]" value="404"
							<?php checked( $settings['blocked_response'], '404' ); ?> />
							<?php esc_html_e( 'Show a 404 (recommended)', 'defyn-security-manager' ); ?></label><br />
						<label><input type="radio" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[blocked_response]" value="redirect"
							<?php checked( $settings['blocked_response'], 'redirect' ); ?> />
							<?php esc_html_e( 'Redirect to:', 'defyn-security-manager' ); ?></label>
						<input type="url" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[blocked_redirect_url]"
						       value="<?php echo esc_attr( $settings['blocked_redirect_url'] ); ?>"
						       placeholder="<?php echo esc_attr( home_url( '/' ) ); ?>" class="regular-text" /><br />
						<label><input type="radio" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[blocked_response]" value="fake"
							<?php checked( $settings['blocked_response'], 'fake' ); ?> />
							<?php esc_html_e( 'Show a decoy login page (always fails)', 'defyn-security-manager' ); ?></label>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="ip_allowlist"><?php esc_html_e( 'IP allowlist (optional)', 'defyn-security-manager' ); ?></label></th>
					<td>
						<textarea id="ip_allowlist" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[ip_allowlist]"
						          rows="4" class="large-text code"
						          placeholder="203.0.113.42&#10;198.51.100.0/24"><?php
							echo esc_textarea( implode( "\n", (array) $settings['ip_allowlist'] ) );
						?></textarea>
						<p class="description">
							<?php esc_html_e( 'One IP or CIDR range per line. When set, only listed IPs can reach the hidden URL. Leave blank to allow all.', 'defyn-security-manager' ); ?>
							<br /><?php esc_html_e( 'Behind a proxy? Define DEFSEC_TRUST_PROXY in wp-config.php to honor X-Forwarded-For.', 'defyn-security-manager' ); ?>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Other auth endpoints', 'defyn-security-manager' ); ?></th>
					<td>
						<label><input type="checkbox" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[hide_xmlrpc]" value="1"
							<?php checked( $settings['hide_xmlrpc'] ); ?> />
							<?php esc_html_e( 'Hide /xmlrpc.php (return the same blocked response as /wp-admin)', 'defyn-security-manager' ); ?></label>
						<p class="description" style="margin-top:4px;">
							<?php esc_html_e( "Safe to enable unless you actively use XML-RPC integrations (e.g. Jetpack, the WP mobile app's classic auth flow, IFTTT). Most modern sites don't need it.", 'defyn-security-manager' ); ?>
						</p>
						<label style="margin-top:10px;display:inline-block;"><input type="checkbox" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[hide_rest_api]" value="1"
							<?php checked( $settings['hide_rest_api'] ); ?> />
							<?php esc_html_e( 'Hide /wp-json (REST API) — BREAKING for most sites', 'defyn-security-manager' ); ?></label>
						<p class="description" style="margin-top:4px;">
							<?php echo wp_kses_post( __( '<strong>Only enable if you know your site doesn\'t use the REST API.</strong> The block editor, Gutenberg, contact-form plugins, and many third-party tools depend on it. Authenticated REST + XML-RPC requests for users in a 2FA-required role are already rejected separately — that protection is on by default and doesn\'t require this checkbox.', 'defyn-security-manager' ) ); ?>
						</p>
					</td>
				</tr>
			</table>

		<?php elseif ( $active_tab === 'security' ) : ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Failed-login throttle', 'defyn-security-manager' ); ?></th>
					<td>
						<label><input type="checkbox" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[throttle_enabled]" value="1"
							<?php checked( $settings['throttle_enabled'] ); ?> />
							<?php esc_html_e( 'Lock out IPs after too many failed attempts', 'defyn-security-manager' ); ?></label>
						<p class="description" style="margin-top:8px;">
							<?php esc_html_e( 'After', 'defyn-security-manager' ); ?>
							<input type="number" min="1" max="50" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[throttle_max_attempts]"
							       value="<?php echo esc_attr( $settings['throttle_max_attempts'] ); ?>" class="small-text" />
							<?php esc_html_e( 'failed attempts within', 'defyn-security-manager' ); ?>
							<input type="number" min="1" max="1440" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[throttle_window_min]"
							       value="<?php echo esc_attr( $settings['throttle_window_min'] ); ?>" class="small-text" />
							<?php esc_html_e( 'minutes, lock out for', 'defyn-security-manager' ); ?>
							<input type="number" min="1" max="10080" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[throttle_lockout_min]"
							       value="<?php echo esc_attr( $settings['throttle_lockout_min'] ); ?>" class="small-text" />
							<?php esc_html_e( 'minutes.', 'defyn-security-manager' ); ?>
						</p>
						<?php
						$active_lockouts = DEFSEC_Throttle::count_active();
						if ( $active_lockouts > 0 ) :
							?>
							<p style="margin-top:14px;padding:10px 14px;background:#fef3c7;border:1px solid #fcd34d;border-radius:4px;">
								<strong><?php
								echo esc_html( sprintf(
									/* translators: %d: number of locked-out IPs */
									_n( '%d IP is currently locked out.', '%d IPs are currently locked out.', (int) $active_lockouts, 'defyn-security-manager' ),
									(int) $active_lockouts
								) );
							?></strong>
								<button type="submit" formaction="<?php echo esc_url( admin_url( 'admin.php' ) ); ?>"
								        formmethod="post" name="defsec_clear_lockouts" value="1"
								        class="button" style="margin-left:12px;"
								        onclick="return confirm('<?php esc_attr_e( 'Clear all active lockouts? Locked-out IPs will be able to attempt login immediately.', 'defyn-security-manager' ); ?>');">
									<?php esc_html_e( 'Clear all lockouts', 'defyn-security-manager' ); ?>
								</button>
								<?php wp_nonce_field( 'defsec_clear_lockouts' ); ?>
							</p>
						<?php endif; ?>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Time-window access', 'defyn-security-manager' ); ?></th>
					<td>
						<label><input type="checkbox" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[time_window_enabled]" value="1"
							<?php checked( $settings['time_window_enabled'] ); ?> />
							<?php esc_html_e( 'Only allow login during these hours', 'defyn-security-manager' ); ?></label>
						<p style="margin-top:8px;">
							<?php esc_html_e( 'From', 'defyn-security-manager' ); ?>
							<input type="time" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[time_window_start]"
							       value="<?php echo esc_attr( $settings['time_window_start'] ); ?>" />
							<?php esc_html_e( 'to', 'defyn-security-manager' ); ?>
							<input type="time" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[time_window_end]"
							       value="<?php echo esc_attr( $settings['time_window_end'] ); ?>" />
							<small style="margin-left:8px;color:#646970;">
								<?php
								printf(
									/* translators: %s: site timezone */
									esc_html__( 'Site timezone: %s', 'defyn-security-manager' ),
									esc_html( wp_timezone_string() )
								);
								?>
							</small>
						</p>
						<p style="margin-top:8px;">
							<?php esc_html_e( 'Days:', 'defyn-security-manager' ); ?>
							<?php foreach ( $days as $i => $label ) : ?>
								<label style="margin-right:8px;">
									<input type="checkbox" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[time_window_days][]" value="<?php echo (int) $i; ?>"
										<?php checked( in_array( $i, $selected_days, true ) ); ?> />
									<?php echo esc_html( $label ); ?>
								</label>
							<?php endforeach; ?>
						</p>
						<p>
							<label for="emergency_bypass_code"><?php esc_html_e( 'Emergency bypass code (optional)', 'defyn-security-manager' ); ?></label><br />
							<input type="text" id="emergency_bypass_code" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[emergency_bypass_code]"
							       placeholder="<?php esc_attr_e( 'Leave blank to keep existing code', 'defyn-security-manager' ); ?>"
							       class="regular-text" autocomplete="off" />
							<p class="description">
								<?php echo wp_kses_post( __( 'If set, appending <code>?defyn_bypass=YOUR_CODE</code> to the hidden URL skips the time-window check for that login. Stored hashed.', 'defyn-security-manager' ) ); ?>
							</p>
						</p>
					</td>
				</tr>
			</table>

		<?php elseif ( $active_tab === '2fa' ) : ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Two-factor authentication', 'defyn-security-manager' ); ?></th>
					<td>
						<label><input type="checkbox" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[two_factor_enabled]" value="1"
							<?php checked( $settings['two_factor_enabled'] ); ?> />
							<?php esc_html_e( 'Enable 2FA across the site', 'defyn-security-manager' ); ?></label>
						<p class="description">
							<?php esc_html_e( 'Users can voluntarily enrol on their profile page. Use the list below to require 2FA for chosen roles.', 'defyn-security-manager' ); ?>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Require 2FA for these roles', 'defyn-security-manager' ); ?></th>
					<td>
						<?php foreach ( $roles_all as $slug => $details ) : ?>
							<label style="display:block;margin-bottom:4px;">
								<input type="checkbox" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[two_factor_required_roles][]"
								       value="<?php echo esc_attr( $slug ); ?>"
									<?php checked( in_array( $slug, (array) $settings['two_factor_required_roles'], true ) ); ?> />
								<?php echo esc_html( translate_user_role( $details['name'] ) ); ?>
							</label>
						<?php endforeach; ?>
						<p class="description"><?php esc_html_e( 'Users in these roles must enrol before they can log in.', 'defyn-security-manager' ); ?></p>
					</td>
				</tr>
			</table>

		<?php elseif ( $active_tab === 'alerts' ) : ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Email alerts', 'defyn-security-manager' ); ?></th>
					<td>
						<label><input type="checkbox" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[alerts_enabled]" value="1"
							<?php checked( $settings['alerts_enabled'] ); ?> />
							<?php esc_html_e( 'Send email notifications', 'defyn-security-manager' ); ?></label>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="alerts_email"><?php esc_html_e( 'Notify email', 'defyn-security-manager' ); ?></label></th>
					<td>
						<input type="email" id="alerts_email" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[alerts_email]"
						       value="<?php echo esc_attr( $settings['alerts_email'] ); ?>" class="regular-text" />
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Send alert when', 'defyn-security-manager' ); ?></th>
					<td>
						<label><input type="checkbox" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[alerts_on_lockout]" value="1"
							<?php checked( $settings['alerts_on_lockout'] ); ?> />
							<?php esc_html_e( 'An IP is locked out for repeated failed logins', 'defyn-security-manager' ); ?></label><br />
						<label><input type="checkbox" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[alerts_on_scan]" value="1"
							<?php checked( $settings['alerts_on_scan'] ); ?> />
							<?php esc_html_e( 'Someone hits the original /wp-admin or /wp-login.php', 'defyn-security-manager' ); ?></label><br />
						<label><input type="checkbox" name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[alerts_on_new_ip_login] " value="1"
							<?php checked( $settings['alerts_on_new_ip_login'] ); ?> />
							<?php esc_html_e( 'A user logs in successfully from an IP not seen before', 'defyn-security-manager' ); ?></label>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="log_retention_days"><?php esc_html_e( 'Activity log retention (days)', 'defyn-security-manager' ); ?></label></th>
					<td>
						<input type="number" min="1" max="365" id="log_retention_days"
						       name="<?php echo esc_attr( DEFSEC_OPTION ); ?>[log_retention_days]"
						       value="<?php echo esc_attr( $settings['log_retention_days'] ); ?>" class="small-text" />
					</td>
				</tr>
			</table>
		<?php endif; ?>

		<?php submit_button(); ?>
	</form>
</div>
