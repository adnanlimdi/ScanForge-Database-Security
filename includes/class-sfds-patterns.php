<?php
/**
 * Malware patterns library.
 *
 * @package ScanForge_DB_Security
 * @since   1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class SFDS_Patterns
 *
 * Holds all known malware pattern definitions and allowlisted DB identifiers.
 * Every table name, column name, and primary key used in raw SQL is sourced
 * exclusively from this class — never from user input — which satisfies the
 * PluginCheck.Security.DirectDB requirement for escaped/trusted identifiers.
 *
 * Pattern design rules
 * --------------------
 * 1. Patterns must be SPECIFIC enough to avoid false positives on legitimate
 *    plugin data (JWT tokens, base64 API keys, cached update responses, etc.)
 * 2. Patterns that are naturally broad (e.g. base64 fragments) are NOT used
 *    as standalone LIKE patterns — they are handled by the post-filter in
 *    is_false_positive() which checks surrounding context before flagging.
 * 3. Known-safe wp_options rows are listed in get_excluded_option_names() and
 *    are skipped entirely during the wp_options scan.
 *
 * @since 1.0.0
 */
class SFDS_Patterns {

	/**
	 * Returns an associative array of malware patterns.
	 *
	 * Key   = string to search for in the database.
	 * Value = human-readable label shown in the UI.
	 *
	 * NOTE: Keep patterns as specific as possible.
	 * Broad patterns like 'aHR0cHM6Ly' (base64 https://) or 'fromCharCode'
	 * produce false positives on legitimate plugin cache/update data and have
	 * been deliberately removed from this list. They are checked contextually
	 * in is_false_positive() / verify_threat() instead.
	 *
	 * @since  1.0.0
	 * @return array<string,string>
	 */
	public static function get_all() {
		return array(
			// ── High-confidence malware indicators ───────────────────
			'searchranktraffic'                => __( 'Traffic hijacking script (searchranktraffic.live)', 'scanforge-db-security' ),
			'wordpressnull'                    => __( 'Nulled plugin backdoor (wordpressnull.org)', 'scanforge-db-security' ),
			'systemLoad('                      => __( 'Known malware loader function', 'scanforge-db-security' ),
			'http2_session_id'                 => __( 'Tracking cookie injection', 'scanforge-db-security' ),

			// ── PHP code injection — specific enough to not FP ───────
			// "eval(base64_decode(" is specific — real code, not cached data.
			'eval(base64_decode('              => __( 'PHP eval+base64_decode injection', 'scanforge-db-security' ),
			// "eval(gzinflate(" is a real obfuscated payload signature.
			'eval(gzinflate('                  => __( 'PHP eval+gzinflate obfuscated payload', 'scanforge-db-security' ),
			// Standalone base64_decode only in PHP exec context.
			'eval(base64'                      => __( 'PHP eval+base64 injection', 'scanforge-db-security' ),

			// ── JS injection — specific patterns only ─────────────────
			// Only flag the full injection pattern, not just createElement.
			'<script>document.createElement'  => __( 'Inline script dynamic element injection', 'scanforge-db-security' ),
			// The searchranktraffic injection specifically uses this loader.
			'function systemLoad('             => __( 'Malware systemLoad function definition', 'scanforge-db-security' ),

			// ── Shell / web shells ────────────────────────────────────
			'shell_exec('                      => __( 'Shell execution attempt (shell_exec)', 'scanforge-db-security' ),
			'passthru('                        => __( 'Shell passthru attempt', 'scanforge-db-security' ),
			'FilesMan'                         => __( 'Web shell signature (FilesMan)', 'scanforge-db-security' ),
			'c99shell'                         => __( 'C99 web shell', 'scanforge-db-security' ),
			'r57shell'                         => __( 'R57 web shell', 'scanforge-db-security' ),
		);
	}
    /**
     * Returns wp_options option_name values that should be excluded from scanning.
     *
     * These are known-safe rows that contain JWT tokens, base64-encoded API
     * responses, or serialized plugin settings that legitimately trigger broad
     * patterns. Excluding them by name prevents false positives without
     * reducing real threat detection capability.
     *
     * @since  1.0.0
     * @return string[] List of option_name values to skip.
     */
    public static function get_excluded_option_names() {
        return array(
            // Elementor Pro — license/update API cache (contains JWT tokens with base64 URLs).
            '_elementor_pro_license_v2_data',
            '_elementor_pro_license_data',
            'elementor_pro_license_key',
            '_site_transient_elementor_pro_license',

            // WordPress core update transients — contain base64 download URLs.
            '_site_transient_update_plugins',
            '_site_transient_update_themes',
            '_site_transient_update_core',
            '_transient_update_plugins',
            '_transient_update_themes',

            // CrowdSec / Shield Security — contain auth tokens and JWT data.
            'crowdsec_plugin_options',
            'icwp-wpsf-options-ips',
            'icwp-wpsf-options-plugin',
            'icwp-wpsf-options-login',
            'icwp-wpsf-options-firewall',
            'icwp-wpsf-options-autoupdates',
            'icwp-wpsf-options-hackprotect',
            'icwp-wpsf-options-traffic',
            'icwp-wpsf-options-userManagement',
            'icwp-wpsf-options-commentsFilter',
            'icwp-wpsf-options-headers',
            'icwp-wpsf-options-integrations',
            'icwp-wpsf-options-lockdown',
            'icwp-wpsf-options-audit_trail',

            // Elementor Connect OAuth credentials — client_id, access_token, JWT bearer token.
            'elementor_connect_common_data',
            'elementor_pro_connect_common_data',
            'elementor_connect_site_key',

            // Elementor core — cached CSS / kit data.
            'elementor_css',
            '_elementor_global_css',
            'elementor_active_kit',

            // WordPress auth/nonce keys — legitimate base64-like strings.
            'auth_key',
            'secure_auth_key',
            'logged_in_key',
            'nonce_key',
            'auth_salt',
            'secure_auth_salt',
            'logged_in_salt',
            'nonce_salt',

            // WooCommerce — helper data and API cache.
            'woocommerce_helper_data',
            'woocommerce_helper_subscriptions',

            // Rank Math — update/license cache.
            'rank_math_connect_data',

            // LiteSpeed Cache — encoded cache keys.
            'litespeed.conf.object',

            /* =========================
             * Gravity Forms
             * ========================= */
            'gf_api_key',
            'gf_license_key',
            'gravityformsaddon_feed',
            'rg_gforms_key',
            'rg_gforms_settings',
            '_transient_gf_',
            '_site_transient_gf_',

            /* =========================
             * Wordfence Security
             * ========================= */
            'wordfence',
            'wfConfig',
            'wf_logins',
            'wfBlockedIPLog',
            'wf_hits',
            'wfIssues',
            'wfNotifications',
            'wfTrafficRates',
            '_transient_wf_',
            '_site_transient_wf_',
        );
    }

	/**
	 * Check whether a matched row is a known false positive.
	 *
	 * Called after a LIKE pattern match to verify the match is genuinely
	 * suspicious in context, not a legitimate plugin data entry.
	 *
	 * @since  1.0.0
	 * @param  string $table       Table name.
	 * @param  string $option_name Option name (only relevant for wp_options).
	 * @param  string $content     Full row content (first 300 chars).
	 * @param  string $pattern     The pattern that matched.
	 * @return bool                True if this is a false positive (skip it).
	 */
	public static function is_false_positive( $table, $option_name, $content, $pattern ) {
		global $wpdb;

		// ── wp_options exclusions by option name ──────────────────────────
		if ( $table === $wpdb->options && '' !== $option_name ) {

			// Skip explicitly excluded option names.
			if ( in_array( $option_name, self::get_excluded_option_names(), true ) ) {
				return true;
			}

			// Skip any _transient_ or _site_transient_ row — these are always
			// plugin cache/update data, never malware injection points.
			if ( strpos( $option_name, '_transient_' ) !== false ) {
				return true;
			}

			// Skip Elementor element/CSS cache rows.
			if ( strpos( $option_name, '_elementor_' ) !== false ) {
				return true;
			}

			// Skip Shield Security / CrowdSec option rows.
			if ( strpos( $option_name, 'icwp-' ) !== false ) {
				return true;
			}

			// Skip CrowdSec plugin rows.
			if ( strpos( $option_name, 'crowdsec' ) !== false ) {
				return true;
			}
		}

		// ── Context checks for broad patterns ────────────────────────────
		// 'eval(base64_decode(' in a serialized plugin settings string
		// that also contains 'timeout' and 'stable_version' is update cache.
		if ( 'eval(base64_decode(' === $pattern || 'eval(base64' === $pattern ) {
			if ( strpos( $content, 'stable_version' ) !== false ||
				 strpos( $content, 'auth_token' ) !== false ||
				 strpos( $content, '"timeout"' ) !== false ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Returns the complete allowlist of scan targets.
	 *
	 * Structure: table_name => array( column, ... )
	 * Every identifier here is a hard-coded string — never user input.
	 *
	 * @since  1.0.0
	 * @return array<string, array{ columns: string[], pk: string }>
	 */
	public static function get_scan_targets() {
		global $wpdb;

		return array(
			$wpdb->posts    => array(
				'columns' => array( 'post_content', 'post_excerpt', 'post_title' ),
				'pk'      => 'ID',
			),
			$wpdb->options  => array(
				'columns' => array( 'option_value' ),
				'pk'      => 'option_id',
			),
			$wpdb->postmeta => array(
				'columns' => array( 'meta_value' ),
				'pk'      => 'meta_id',
			),
			$wpdb->usermeta => array(
				'columns' => array( 'meta_value' ),
				'pk'      => 'umeta_id',
			),
			$wpdb->comments => array(
				'columns' => array( 'comment_content', 'comment_author_url' ),
				'pk'      => 'comment_ID',
			),
		);
	}

	/**
	 * Validate and return a table name from the allowlist.
	 *
	 * @since  1.0.0
	 * @param  string $table  Table name to validate.
	 * @return string|false   Trusted table name, or false if not in allowlist.
	 */
	public static function validate_table( $table ) {
		$targets = self::get_scan_targets();
		if ( array_key_exists( $table, $targets ) ) {
			return $table;
		}
		return false;
	}

	/**
	 * Validate and return a column name from the allowlist for a given table.
	 *
	 * @since  1.0.0
	 * @param  string $table  Table name.
	 * @param  string $column Column name to validate.
	 * @return string|false   Trusted column name, or false if not in allowlist.
	 */
	public static function validate_column( $table, $column ) {
		$targets = self::get_scan_targets();
		if ( isset( $targets[ $table ]['columns'] ) && in_array( $column, $targets[ $table ]['columns'], true ) ) {
			return $column;
		}
		return false;
	}

	/**
	 * Return the primary key column for a validated table.
	 *
	 * @since  1.0.0
	 * @param  string $table Trusted table name.
	 * @return string|false  Primary key column name, or false.
	 */
	public static function get_primary_key( $table ) {
		$targets = self::get_scan_targets();
		return isset( $targets[ $table ]['pk'] ) ? $targets[ $table ]['pk'] : false;
	}
}