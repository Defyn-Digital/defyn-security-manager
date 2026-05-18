<?php
/**
 * Plugin Name:       Defyn Security Manager
 * Plugin URI:        https://wordpress.org/plugins/defyn-security-manager/
 * Description:       Hide the WordPress login behind a custom URL. Throttle brute-force attempts, enforce two-factor authentication, restrict access by IP and time, and audit every login event from a built-in activity log.
 * Version:           1.0.0
 * Requires at least: 6.2
 * Requires PHP:      7.4
 * Author:            Defyn
 * Author URI:        https://defyn.com.au
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       defyn-security-manager
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'DEFSEC_VERSION', '1.0.0' );
define( 'DEFSEC_FILE', __FILE__ );
define( 'DEFSEC_PATH', plugin_dir_path( __FILE__ ) );
define( 'DEFSEC_URL', plugin_dir_url( __FILE__ ) );
define( 'DEFSEC_BASENAME', plugin_basename( __FILE__ ) );
define( 'DEFSEC_SLUG', 'defyn-security-manager' );
define( 'DEFSEC_OPTION', 'defsec_settings' );

require_once DEFSEC_PATH . 'includes/helpers.php';
require_once DEFSEC_PATH . 'includes/class-options.php';
require_once DEFSEC_PATH . 'includes/class-activity-log.php';
require_once DEFSEC_PATH . 'includes/class-email-alerts.php';
require_once DEFSEC_PATH . 'includes/class-throttle.php';
require_once DEFSEC_PATH . 'includes/class-time-window.php';
require_once DEFSEC_PATH . 'includes/totp.php';
require_once DEFSEC_PATH . 'includes/class-qr.php';
require_once DEFSEC_PATH . 'includes/class-two-factor.php';
require_once DEFSEC_PATH . 'includes/class-hidden-login.php';
require_once DEFSEC_PATH . 'includes/class-api-guard.php';
require_once DEFSEC_PATH . 'includes/class-activator.php';
require_once DEFSEC_PATH . 'includes/class-deactivator.php';
require_once DEFSEC_PATH . 'admin/class-admin.php';
require_once DEFSEC_PATH . 'includes/class-plugin.php';

register_activation_hook( __FILE__, [ 'DEFSEC_Activator', 'activate' ] );
register_deactivation_hook( __FILE__, [ 'DEFSEC_Deactivator', 'deactivate' ] );

add_action( 'plugins_loaded', static function () {
	DEFSEC_Plugin::instance()->boot();
}, 1 );
