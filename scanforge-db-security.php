<?php
/**
 * Plugin Name:       ScanForge Database Security
 * Plugin URI:        https://adnanlimdiwala.wordpress.com/
 * Description:       Scans and removes malicious scripts and malware injections from your WordPress database tables.
 * Version:           1.0.0
 * Requires at least: 5.0
 * Requires PHP:      7.4
 * Author:            adnanlimdi
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       scanforge-db-security
 * Domain Path:       /languages
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Define plugin constants.
define( 'SFDS_VERSION',     '1.0.0' );
define( 'SFDS_PLUGIN_DIR',  plugin_dir_path( __FILE__ ) );
define( 'SFDS_PLUGIN_URL',  plugins_url( '/', __FILE__ ) );
define( 'SFDS_PLUGIN_FILE', __FILE__ );

// Load includes.
require_once SFDS_PLUGIN_DIR . 'includes/class-sfds-patterns.php';
require_once SFDS_PLUGIN_DIR . 'includes/class-sfds-scanner.php';
require_once SFDS_PLUGIN_DIR . 'includes/class-sfds-cleaner.php';
require_once SFDS_PLUGIN_DIR . 'includes/class-sfds-admin.php';

/**
 * Initialise the plugin.
 *
 * @since 1.0.0
 */
function sfds_init() {
	$admin = new SFDS_Admin();
	$admin->init();
}
add_action( 'plugins_loaded', 'sfds_init' );
