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
 * @since 1.0.0
 */
class SFDS_Patterns {

	/**
	 * Returns an associative array of malware patterns.
	 *
	 * Key   = string to search for in the database.
	 * Value = human-readable label shown in the UI.
	 *
	 * @since  1.0.0
	 * @return array<string,string>
	 */
	public static function get_all() {
		return array(
			'searchranktraffic'               => __( 'Traffic hijacking script (searchranktraffic.live)', 'scanforge-db-security' ),
			'wordpressnull'                   => __( 'Nulled plugin backdoor (wordpressnull.org)', 'scanforge-db-security' ),
			'base64_decode'                   => __( 'Base64 decode payload', 'scanforge-db-security' ),
			'eval(gzinflate'                  => __( 'Obfuscated gzinflate eval payload', 'scanforge-db-security' ),
			'eval(base64'                     => __( 'Base64 eval injection', 'scanforge-db-security' ),
			"document.createElement('script')" => __( 'Dynamic script element injection', 'scanforge-db-security' ),
			'systemLoad('                     => __( 'Known malware loader function', 'scanforge-db-security' ),
			'http2_session_id'                => __( 'Tracking cookie injection', 'scanforge-db-security' ),
			'fromCharCode'                    => __( 'Character code obfuscation', 'scanforge-db-security' ),
			'shell_exec('                     => __( 'Shell execution attempt', 'scanforge-db-security' ),
			'passthru('                       => __( 'Shell passthru attempt', 'scanforge-db-security' ),
			'FilesMan'                        => __( 'Web shell signature (FilesMan)', 'scanforge-db-security' ),
			'c99shell'                        => __( 'C99 web shell', 'scanforge-db-security' ),
			'r57shell'                        => __( 'R57 web shell', 'scanforge-db-security' ),
			'aHR0cHM6Ly'                      => __( 'Base64-encoded URL payload', 'scanforge-db-security' ),
		);
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
