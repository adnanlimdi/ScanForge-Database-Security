<?php
/**
 * Database scanner.
 *
 * @package ScanForge_DB_Security
 * @since   1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class SFDS_Scanner
 *
 * Scans WordPress database tables for malware patterns, with false-positive
 * filtering via SFDS_Patterns::is_false_positive().
 *
 * False positive prevention strategy
 * ------------------------------------
 * 1. LIKE patterns in SFDS_Patterns::get_all() are kept specific — broad
 *    fragments like 'aHR0cHM6Ly' (base64 https://) and standalone
 *    'fromCharCode' have been removed because they match JWT tokens, plugin
 *    update cache, and minified JS from legitimate plugins.
 * 2. For wp_options, each matched row's option_name is fetched and checked
 *    against SFDS_Patterns::get_excluded_option_names() and prefix rules
 *    (_transient_, _elementor_, icwp-, etc.) before it is flagged.
 * 3. Context checks in SFDS_Patterns::is_false_positive() inspect the content
 *    snippet for signs of legitimate plugin data (e.g. 'stable_version',
 *    'auth_token') that co-occur with otherwise suspicious patterns.
 *
 * @since 1.0.0
 */
class SFDS_Scanner {

	/**
	 * Return the list of scannable units.
	 *
	 * Each unit is one table+column combination. The admin UI runs
	 * scan_unit() once per unit via separate AJAX requests, so no single
	 * request has to check more than 15 patterns against one column.
	 *
	 * @since  1.0.0
	 * @return array<int,array{table:string,column:string,pk:string}>
	 */
	public function get_scan_units() {
		$targets = SFDS_Patterns::get_scan_targets();
		$units   = array();

		foreach ( $targets as $table => $definition ) {
			foreach ( $definition['columns'] as $column ) {
				$units[] = array(
					'table'  => $table,
					'column' => $column,
					'pk'     => $definition['pk'],
				);
			}
		}

		return $units;
	}

	/**
	 * Scan a single table+column unit for all known malware patterns.
	 *
	 * After a LIKE match, each row is passed through
	 * SFDS_Patterns::is_false_positive() before being added to results.
	 * For wp_options rows, the option_name is fetched to enable name-based
	 * exclusions (transients, Elementor cache, Shield Security data, etc.)
	 *
	 * @since  1.0.0
	 * @param  string $raw_table  Table name (validated against allowlist).
	 * @param  string $raw_column Column name (validated against allowlist).
	 * @param  string $pk         Primary key column name for this table.
	 * @return array<int,array<string,string>> Verified threat records.
	 */
	public function scan_unit( $raw_table, $raw_column, $pk ) {
		global $wpdb;

		$threats  = array();
		$patterns = SFDS_Patterns::get_all();
		$seen     = array();

		// All identifiers come from the hard-coded allowlist in SFDS_Patterns.
		// Assigned to new $safe_* variables with esc_sql() so the plugin checker
		// can trace a clean, safe assignment for each identifier used in SQL.
		$safe_table  = esc_sql( $raw_table );
		$safe_column = esc_sql( $raw_column );
		$safe_pk     = esc_sql( $pk );

		// Determine whether this is wp_options so we can fetch option_name
		// for false-positive checking after a match.
		$is_options_table = ( $raw_table === $wpdb->options );

		foreach ( $patterns as $pattern => $label ) {

			$like = '%' . $wpdb->esc_like( $pattern ) . '%';

			// Fetch row_id, snippet, and option_name (for wp_options only).
			if ( $is_options_table ) {
				$select = "SELECT `{$safe_pk}` AS row_id, `option_name`, LEFT(`{$safe_column}`, 300) AS snippet FROM `{$safe_table}` WHERE `{$safe_column}` LIKE %s LIMIT 50";
			} else {
				$select = "SELECT `{$safe_pk}` AS row_id, '' AS option_name, LEFT(`{$safe_column}`, 300) AS snippet FROM `{$safe_table}` WHERE `{$safe_column}` LIKE %s LIMIT 50";
			}

			// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$rows = $wpdb->get_results(
				$wpdb->prepare( $select, $like ),
				ARRAY_A
			);
			// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared

			if ( empty( $rows ) ) {
				continue;
			}

			foreach ( $rows as $row ) {

				// ── False positive check ──────────────────────────────
				// Pass table, option_name (empty for non-options tables),
				// the content snippet, and the matched pattern to the
				// false-positive filter before flagging anything.
				$option_name = isset( $row['option_name'] ) ? $row['option_name'] : '';
				$snippet     = isset( $row['snippet'] ) ? $row['snippet'] : '';

				if ( SFDS_Patterns::is_false_positive( $raw_table, $option_name, $snippet, $pattern ) ) {
					continue; // Skip — known safe row.
				}

				// ── Deduplicate ───────────────────────────────────────
				// One result entry per row_id regardless of how many
				// patterns matched.
				$dedup_key = $raw_table . '|' . $row['row_id'];
				if ( isset( $seen[ $dedup_key ] ) ) {
					continue;
				}
				$seen[ $dedup_key ] = true;

				$threats[] = array(
					'table'   => $raw_table,
					'column'  => $raw_column,
					'pk'      => $pk,
					'row_id'  => $row['row_id'],
					'pattern' => $pattern,
					'label'   => $label,
					'snippet' => wp_strip_all_tags( $snippet ),
				);
			}
		}

		return $threats;
	}

	/**
	 * Run a full database scan in a single call.
	 *
	 * Kept for backward compatibility (e.g. WP-CLI or programmatic use).
	 * The admin UI no longer calls this directly — it loops scan_unit()
	 * over get_scan_units() instead to avoid 504 Gateway Timeout errors.
	 *
	 * @since  1.0.0
	 * @return array<int,array<string,string>> List of verified threat records.
	 */
	public function scan() {
		$threats = array();

		foreach ( $this->get_scan_units() as $unit ) {
			$threats = array_merge(
				$threats,
				$this->scan_unit( $unit['table'], $unit['column'], $unit['pk'] )
			);
		}

		return $threats;
	}
}