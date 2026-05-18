<?php
/**
 * Hidden-login engine.
 *
 * Two responsibilities:
 *   1. Make /wp-login.php (and /wp-admin for non-authenticated users) effectively
 *      invisible to anyone hitting them directly — configurable to 404, redirect,
 *      or show a fake login.
 *   2. Expose the chosen slug as the real login route, transparently routing it
 *      to wp-login.php under the hood.
 *
 * Approach borrows from WPS Hide Login: intercept on `plugins_loaded` and
 * `setup_theme` (early enough to override default routing); filter `site_url`
 * variants so WordPress-generated login URLs all point at the new slug.
 *
 * IP allowlist: if configured, only allowlisted IPs can reach the hidden slug.
 * Everyone else gets the "blocked" response, just like /wp-login.php hitters.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class DEFSEC_Hidden_Login {

	private bool $wp_login_php = false;

	public function boot(): void {
		// Hook on setup_theme rather than plugins_loaded — wp-login.php (which
		// we include for the hidden URL) depends on WP_FUNCTIONALITY constants
		// like AUTOSAVE_INTERVAL, which wp_functionality_constants() defines
		// AFTER plugins_loaded fires (wp-settings.php line 596 vs line 593).
		// setup_theme is the earliest hook that runs after those constants land.
		add_action( 'setup_theme', [ $this, 'on_request' ], 1 );
		add_action( 'wp_loaded', [ $this, 'on_wp_loaded' ] );

		add_filter( 'site_url', [ $this, 'filter_login_url' ], 10, 4 );
		add_filter( 'network_site_url', [ $this, 'filter_login_url' ], 10, 3 );
		add_filter( 'wp_redirect', [ $this, 'filter_wp_redirect' ], 10, 2 );

		add_filter( 'login_url', [ $this, 'filter_login_url_alias' ], 10, 3 );
		add_filter( 'logout_redirect', [ $this, 'filter_logout_redirect' ], 10, 3 );
	}

	public function on_request(): void {
		global $pagenow;

		$request = $this->parse_request();
		$slug    = $this->slug();
		$path    = $request['path'];

		// Allowlist enforcement: only matters for actually-hitting the hidden slug.
		$allowlist = (array) DEFSEC_Options::get( 'ip_allowlist', [] );
		$ip        = defsec_client_ip();
		$allow_ok  = empty( $allowlist ) || defsec_ip_in_list( $ip, $allowlist );

		// Hitting the hidden slug = render wp-login.php.
		if ( $path === $slug || $path === $slug . '/' ) {
			if ( ! $allow_ok ) {
				$this->respond_blocked( 'allowlist_block' );
				exit;
			}
			$this->serve_wp_login();
			exit;
		}

		// Hitting /wp-login.php directly.
		if ( $path === 'wp-login.php' || $this->is_login_php_request( $request ) ) {
			// Allow if user is already logged in (e.g. coming from admin link),
			// or for explicit `?action=` flows that aren't a login (logout, postpass).
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only inspection of the standard WP wp-login.php ?action= parameter; no state mutation here.
			$action = isset( $_GET['action'] ) ? sanitize_key( wp_unslash( $_GET['action'] ) ) : '';
			$safe_actions = [ 'logout', 'postpass', 'rp', 'resetpass', 'lostpassword' ];

			if ( is_user_logged_in() || in_array( $action, $safe_actions, true ) ) {
				return;
			}

			DEFSEC_Activity_Log::record( DEFSEC_Activity_Log::EVT_HIDDEN_URL_SCAN, [
				'details' => [ 'target' => 'wp-login.php', 'action' => $action ],
			] );
			$this->respond_blocked( 'wp_login_php' );
			exit;
		}

		// Hitting /wp-admin/* while not logged in.
		if ( strpos( $path, 'wp-admin' ) === 0 && ! is_user_logged_in() ) {
			// admin-ajax.php is fine — must remain reachable for unauthenticated AJAX.
			if ( strpos( $path, 'wp-admin/admin-ajax.php' ) === 0 ) {
				return;
			}
			DEFSEC_Activity_Log::record( DEFSEC_Activity_Log::EVT_HIDDEN_URL_SCAN, [
				'details' => [ 'target' => $path ],
			] );
			$this->respond_blocked( 'wp_admin' );
			exit;
		}
	}

	public function on_wp_loaded(): void {
		// If the user's just logged out, send them to the hidden slug instead of
		// wp-login.php so the original URL stays hidden in browser history.
		global $pagenow;
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only check for WP-issued "loggedout" query flag; redirect target is internal-only.
		if ( $pagenow === 'wp-login.php' && isset( $_GET['loggedout'] ) ) {
			wp_safe_redirect( $this->hidden_url( [ 'loggedout' => 'true' ] ) );
			exit;
		}
	}

	public function serve_wp_login(): void {
		// Pretend the request was for wp-login.php so the rest of WP behaves naturally.
		$_SERVER['REQUEST_URI'] = '/wp-login.php' . ( ! empty( $_SERVER['QUERY_STRING'] ) ? '?' . sanitize_text_field( wp_unslash( $_SERVER['QUERY_STRING'] ) ) : '' );
		require ABSPATH . 'wp-login.php';
	}

	public function respond_blocked( string $reason ): void {
		$mode = (string) DEFSEC_Options::get( 'blocked_response', '404' );

		switch ( $mode ) {
			case 'redirect':
				$url = (string) DEFSEC_Options::get( 'blocked_redirect_url', '' );
				if ( $url === '' ) {
					$url = home_url( '/' );
				}
				// phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- Admin-configured external redirect target (honeypot, decoy, etc.); using wp_safe_redirect() would defeat the feature by blocking external hosts.
				wp_redirect( esc_url_raw( $url ) );
				exit;

			case 'fake':
				status_header( 200 );
				nocache_headers();
				$this->render_fake_login();
				exit;

			case '404':
			default:
				global $wp_query;
				if ( ! $wp_query ) {
					$wp_query = new WP_Query();
				}
				$wp_query->set_404();
				status_header( 404 );
				nocache_headers();

				// Try to serve the theme's 404 template; fall back to a minimal one.
				$template = get_404_template();
				if ( $template && file_exists( $template ) ) {
					include $template;
				} else {
					echo '<!doctype html><html><head><meta charset="utf-8"><title>404</title></head><body><h1>Not Found</h1></body></html>';
				}
				exit;
		}
	}

	/**
	 * Minimal decoy login. Always-fails — POST is silently dropped.
	 *
	 * The CSS and JS are externalised to assets/css/fake-login.css and
	 * assets/js/fake-login.js, served via manual <link> / <script> tags
	 * because this output bypasses the WordPress theme + enqueue pipeline
	 * entirely (wp_head() would never fire here).
	 */
	private function render_fake_login(): void {
		$site_name   = get_bloginfo( 'name' );
		$nonce_token = wp_generate_password( 10, false );
		$css_url     = DEFSEC_URL . 'assets/css/fake-login.css?v=' . rawurlencode( DEFSEC_VERSION );
		$js_url      = DEFSEC_URL . 'assets/js/fake-login.js?v=' . rawurlencode( DEFSEC_VERSION );
		?>
<!doctype html>
<html><head>
<meta charset="utf-8" />
<title>Log In &lsaquo; <?php echo esc_html( $site_name ); ?></title>
<?php // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedStylesheet -- This output bypasses the WP theme/enqueue pipeline; wp_head() never fires for the decoy login. Manual <link> tag is the equivalent. ?>
<link rel="stylesheet" href="<?php echo esc_url( $css_url ); ?>" />
</head><body>
<div class="box">
  <h1><?php echo esc_html( $site_name ); ?></h1>
  <div class="err" id="defsec-fake-err">Invalid username or password.</div>
  <form method="post">
    <label>Username or Email Address</label>
    <input type="text" name="log" autocomplete="username" />
    <label>Password</label>
    <input type="password" name="pwd" autocomplete="current-password" />
    <button type="submit">Log In</button>
    <input type="hidden" name="_t" value="<?php echo esc_attr( $nonce_token ); ?>" />
  </form>
</div>
<?php // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript -- This output bypasses the WP theme/enqueue pipeline; wp_footer() never fires for the decoy login. Manual <script src> tag is the equivalent. ?>
<script src="<?php echo esc_url( $js_url ); ?>"></script>
</body></html>
		<?php
	}

	private function is_login_php_request( array $request ): bool {
		// Catches /wp-login.php with any querystring or trailing slash.
		return (bool) preg_match( '#(^|/)wp-login\.php(/|$)#', $request['path_raw'] );
	}

	private function parse_request(): array {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/';
		$path = wp_parse_url( $uri, PHP_URL_PATH ) ?: '/';
		$home = wp_parse_url( home_url( '/' ), PHP_URL_PATH ) ?: '/';
		$home = '/' . trim( $home, '/' );

		// Strip subdirectory install prefix.
		if ( $home !== '/' && strpos( $path, $home ) === 0 ) {
			$path = substr( $path, strlen( $home ) );
		}
		$normalized = trim( $path, '/' );

		return [
			'path'     => $normalized,
			'path_raw' => $path,
		];
	}

	public function slug(): string {
		return (string) DEFSEC_Options::get( 'login_slug', 'defyn-login' );
	}

	public function hidden_url( array $args = [] ): string {
		$url = home_url( '/' . $this->slug() );
		if ( $args ) {
			$url = add_query_arg( $args, $url );
		}
		return $url;
	}

	/**
	 * Rewrite WP-generated login URLs to use the hidden slug.
	 */
	public function filter_login_url( $url, $path, $scheme = null, $blog_id = null ) {
		if ( strpos( (string) $url, 'wp-login.php' ) === false ) {
			return $url;
		}
		$parts = wp_parse_url( $url );
		$query = isset( $parts['query'] ) ? '?' . $parts['query'] : '';
		return home_url( '/' . $this->slug() . $query, $scheme );
	}

	public function filter_login_url_alias( $login_url, $redirect, $force_reauth ) {
		return $this->filter_login_url( $login_url, '', null );
	}

	public function filter_wp_redirect( $location, $status ) {
		if ( is_string( $location ) && strpos( $location, 'wp-login.php' ) !== false ) {
			$location = $this->filter_login_url( $location, '', null );
		}
		return $location;
	}

	public function filter_logout_redirect( $redirect_to, $requested, $user ) {
		if ( $requested && $requested !== admin_url() ) {
			return $requested;
		}
		return $this->hidden_url( [ 'loggedout' => 'true' ] );
	}
}
