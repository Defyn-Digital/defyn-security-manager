<?php
/**
 * Two-factor (TOTP) authentication.
 *
 * Two-stage login: WordPress validates credentials normally; if 2FA is enabled
 * for the user, we then short-circuit the login completion and present a code
 * form. Only after the code (or a one-time backup code) verifies does the user
 * actually get a session cookie.
 *
 * Storage:
 *   - usermeta `dsm_2fa_secret`        (Base32 secret)
 *   - usermeta `dsm_2fa_enabled`       (bool flag)
 *   - usermeta `dsm_2fa_backup_codes`  (array of wp_hash_password hashes)
 *
 * Hashed backup codes mean a DB leak doesn't reveal usable codes.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class DSM_Two_Factor {

	const META_SECRET   = 'dsm_2fa_secret';
	const META_ENABLED  = 'dsm_2fa_enabled';
	const META_BACKUP   = 'dsm_2fa_backup_codes';
	const PENDING_TTL   = 300; // seconds for which the credential check stays valid while user enters their code

	public function boot(): void {
		// Intercept after WP has validated credentials.
		add_filter( 'authenticate', [ $this, 'maybe_require_code' ], 100, 3 );

		// Render the code-entry screen on wp-login.php?action=dsm_2fa
		add_action( 'login_form_dsm_2fa', [ $this, 'handle_code_form' ] );

		// User profile screen: enrollment UI
		add_action( 'show_user_profile', [ $this, 'render_user_profile' ] );
		add_action( 'edit_user_profile', [ $this, 'render_user_profile' ] );
		add_action( 'personal_options_update', [ $this, 'handle_profile_save' ] );
		add_action( 'edit_user_profile_update', [ $this, 'handle_profile_save' ] );
	}

	public static function user_has_2fa( int $user_id ): bool {
		return (bool) get_user_meta( $user_id, self::META_ENABLED, true );
	}

	public static function user_must_have_2fa( WP_User $user ): bool {
		if ( ! DSM_Options::get( 'two_factor_enabled' ) ) {
			return false;
		}
		$required = (array) DSM_Options::get( 'two_factor_required_roles', [] );
		return (bool) array_intersect( $user->roles, $required );
	}

	/**
	 * After WP's credential check, if the user has 2FA, swap the result for a pending state.
	 */
	public function maybe_require_code( $user, $username, $password ) {
		if ( ! $user instanceof WP_User ) {
			return $user;
		}
		if ( empty( $password ) ) {
			return $user; // not a credential submission (e.g. cookie auth)
		}

		$has_2fa  = self::user_has_2fa( $user->ID );
		$must_2fa = self::user_must_have_2fa( $user );

		if ( ! $has_2fa && $must_2fa ) {
			// Required by policy but not yet set up: block with a clear message.
			return new WP_Error(
				'dsm_2fa_required',
				sprintf(
					__( '<strong>Two-factor authentication is required.</strong> Ask an administrator to help you enrol, then log in again.', 'defyn-security-manager' )
				)
			);
		}
		if ( ! $has_2fa ) {
			return $user;
		}

		// Stash a short-lived pending token, redirect to the code form.
		$token = $this->issue_pending_token( $user->ID );

		$redirect = add_query_arg( [
			'action' => 'dsm_2fa',
			'token'  => $token,
		], wp_login_url() );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- 2FA flow: $_REQUEST['redirect_to'] is the standard WP login redirect target and is escaped via esc_url_raw before use. The opaque pending-session token issued earlier in this method serves as the per-request authenticator.
		if ( isset( $_REQUEST['redirect_to'] ) ) {
			$redirect = add_query_arg( 'redirect_to', rawurlencode( esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) ), $redirect );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Renders & processes the code-entry form on wp-login.php.
	 *
	 * NOTE on nonces: the 2FA challenge form intentionally does not use a
	 * wp_nonce_field; the short-lived opaque pending-session token issued by
	 * maybe_require_code() IS the per-request token. Plugin Check flags this
	 * but the design is deliberate.
	 */
	public function handle_code_form(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- 2FA challenge: opaque pending-session token in $_REQUEST['token'] is the per-request authenticator (see consume_pending_token()).
		$token   = isset( $_REQUEST['token'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['token'] ) ) : '';
		$user_id = $this->consume_pending_token( $token, false );

		if ( ! $user_id ) {
			wp_die( esc_html__( 'This 2FA session has expired. Please log in again.', 'defyn-security-manager' ), 403 );
		}

		$error = '';
		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- See class doc above: opaque pending-session token IS the per-request authenticator for this form.
			$code = isset( $_POST['dsm_code'] ) ? sanitize_text_field( wp_unslash( $_POST['dsm_code'] ) ) : '';
			if ( $this->verify_code( $user_id, $code ) ) {
				$this->consume_pending_token( $token, true );

				// phpcs:disable WordPress.Security.NonceVerification.Recommended -- 2FA challenge form; opaque pending-session token consumed above is the per-request authenticator. redirect_to is escaped via esc_url_raw; rememberme is cast to bool.
				$redirect_to = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : admin_url();
				wp_set_auth_cookie( $user_id, ! empty( $_REQUEST['rememberme'] ) );
				// phpcs:enable WordPress.Security.NonceVerification.Recommended

				$user = get_user_by( 'id', $user_id );
				do_action( 'wp_login', $user->user_login, $user );
				DSM_Activity_Log::record( DSM_Activity_Log::EVT_2FA_SUCCESS, [
					'user_id'  => $user_id,
					'username' => $user->user_login,
				] );

				wp_safe_redirect( $redirect_to );
				exit;
			}

			DSM_Activity_Log::record( DSM_Activity_Log::EVT_2FA_FAILED, [
				'user_id' => $user_id,
			] );

			// Same lockout counter as password failures — an attacker can't sidestep
			// the IP lockout by mixing password and 2FA guesses.
			if ( DSM_Options::get( 'throttle_enabled' ) ) {
				$ip = dsm_client_ip();
				if ( ! dsm_ip_in_list( $ip, (array) DSM_Options::get( 'ip_allowlist', [] ) ) ) {
					$user = get_user_by( 'id', $user_id );
					DSM_Throttle::increment_for_ip( $ip, $user ? $user->user_login : '', false );
					// If that increment tripped the threshold, stop here — the lockout
					// guard will catch the next browser POST and short-circuit auth.
					if ( ( new DSM_Throttle() )->is_locked_out( $ip ) ) {
						wp_die(
							esc_html__( 'Too many failed attempts. Try again later.', 'defyn-security-manager' ),
							'',
							[ 'response' => 403 ]
						);
					}
				}
			}

			$error = __( 'Invalid code. Try again.', 'defyn-security-manager' );
		}

		login_header( __( 'Two-factor verification', 'defyn-security-manager' ), '', $error ? new WP_Error( '2fa', $error ) : null );
		?>
		<form method="post" id="defyn-bem-2fa-form">
			<p>
				<label for="dsm_code"><?php esc_html_e( 'Authentication code', 'defyn-security-manager' ); ?></label>
				<input type="text" name="dsm_code" id="dsm_code" class="input"
				       autocomplete="one-time-code" inputmode="numeric" autofocus
				       style="font-size:1.4em;letter-spacing:0.3em;text-align:center;" />
			</p>
			<p class="description" style="margin-top:-8px;">
				<?php esc_html_e( 'Open your authenticator app, or enter a backup code (formatted XXXXX-XXXXX).', 'defyn-security-manager' ); ?>
			</p>
			<input type="hidden" name="token" value="<?php echo esc_attr( $token ); ?>" />
			<?php
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- See handle_code_form() doc: 2FA challenge uses an opaque pending-session token instead of a wp_nonce.
			$redirect_to_input = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';
			?>
			<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to_input ); ?>" />
			<p class="submit">
				<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'defyn-security-manager' ); ?>" />
			</p>
		</form>
		<?php
		login_footer( 'dsm_code' );
		exit;
	}

	/**
	 * Pending-token storage uses transients: short-lived, opaque, single-use.
	 */
	private function issue_pending_token( int $user_id ): string {
		$token = bin2hex( random_bytes( 16 ) );
		set_transient( 'dsm_2fa_pending_' . $token, $user_id, self::PENDING_TTL );
		return $token;
	}

	private function consume_pending_token( string $token, bool $delete ): int {
		if ( $token === '' ) {
			return 0;
		}
		$user_id = (int) get_transient( 'dsm_2fa_pending_' . $token );
		if ( ! $user_id ) {
			return 0;
		}
		if ( $delete ) {
			delete_transient( 'dsm_2fa_pending_' . $token );
		}
		return $user_id;
	}

	/**
	 * Verify a TOTP code or one of the user's hashed backup codes.
	 */
	private function verify_code( int $user_id, string $code ): bool {
		$code = trim( $code );
		if ( $code === '' ) {
			return false;
		}

		// Try TOTP first.
		$secret = (string) get_user_meta( $user_id, self::META_SECRET, true );
		if ( $secret && DSM_TOTP::verify( $secret, $code ) ) {
			return true;
		}

		// Then backup codes.
		$codes = (array) get_user_meta( $user_id, self::META_BACKUP, true );
		foreach ( $codes as $i => $hash ) {
			if ( $hash && wp_check_password( strtoupper( $code ), $hash ) ) {
				unset( $codes[ $i ] );
				update_user_meta( $user_id, self::META_BACKUP, array_values( $codes ) );
				return true;
			}
		}
		return false;
	}

	/**
	 * Enrollment UI shown on the user profile page.
	 */
	public function render_user_profile( WP_User $user ): void {
		if ( ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}
		$enabled = self::user_has_2fa( $user->ID );
		$secret  = (string) get_user_meta( $user->ID, self::META_SECRET, true );

		if ( ! $secret ) {
			$secret = DSM_TOTP::generate_secret();
			update_user_meta( $user->ID, self::META_SECRET, $secret );
		}

		$uri = DSM_TOTP::provisioning_uri(
			$secret,
			$user->user_email,
			wp_specialchars_decode( get_bloginfo( 'name' ) )
		);

		$backup_codes = (array) get_user_meta( $user->ID, self::META_BACKUP, true );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only check for our own post-action redirect query flag; no state mutation here.
		$new_codes    = isset( $_GET['dsm_show_codes'] ) ? get_transient( 'dsm_new_codes_' . $user->ID ) : null;

		include DSM_PATH . 'admin/views/user-2fa-profile.php';
	}

	public function handle_profile_save( int $user_id ): void {
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}

		$action = isset( $_POST['dsm_2fa_action'] ) ? sanitize_key( wp_unslash( $_POST['dsm_2fa_action'] ) ) : '';
		if ( $action === '' ) {
			return;
		}
		check_admin_referer( 'dsm_2fa_' . $user_id );

		switch ( $action ) {
			case 'enable':
				$secret = (string) get_user_meta( $user_id, self::META_SECRET, true );
				$code   = isset( $_POST['dsm_enroll_code'] ) ? sanitize_text_field( wp_unslash( $_POST['dsm_enroll_code'] ) ) : '';
				if ( ! $secret || ! DSM_TOTP::verify( $secret, $code ) ) {
					add_action( 'user_profile_update_errors', static function ( $errors ) {
						$errors->add( 'dsm_2fa', __( 'Verification code did not match. Try again.', 'defyn-security-manager' ) );
					}, 10, 1 );
					return;
				}
				update_user_meta( $user_id, self::META_ENABLED, 1 );
				$plain = DSM_TOTP::generate_backup_codes();
				$hashed = array_map( 'wp_hash_password', $plain );
				update_user_meta( $user_id, self::META_BACKUP, $hashed );
				set_transient( 'dsm_new_codes_' . $user_id, $plain, 600 );

				DSM_Activity_Log::record( DSM_Activity_Log::EVT_2FA_ENROLLED, [
					'user_id'  => $user_id,
				] );

				add_filter( 'wp_redirect', static function ( $loc ) {
					return add_query_arg( 'dsm_show_codes', '1', $loc );
				} );
				break;

			case 'disable':
				delete_user_meta( $user_id, self::META_ENABLED );
				delete_user_meta( $user_id, self::META_SECRET );
				delete_user_meta( $user_id, self::META_BACKUP );
				DSM_Activity_Log::record( DSM_Activity_Log::EVT_2FA_DISABLED, [
					'user_id'  => $user_id,
				] );
				break;

			case 'regenerate_codes':
				if ( ! self::user_has_2fa( $user_id ) ) {
					return;
				}
				$plain  = DSM_TOTP::generate_backup_codes();
				$hashed = array_map( 'wp_hash_password', $plain );
				update_user_meta( $user_id, self::META_BACKUP, $hashed );
				set_transient( 'dsm_new_codes_' . $user_id, $plain, 600 );
				add_filter( 'wp_redirect', static function ( $loc ) {
					return add_query_arg( 'dsm_show_codes', '1', $loc );
				} );
				break;
		}
	}
}
