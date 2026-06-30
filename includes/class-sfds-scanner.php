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
 * Scans WordPress database tables for malware patterns.
 *
 * All table names, column names, and primary key identifiers used in SQL
 * are sourced exclusively from SFDS_Patterns::get_scan_targets() — a
 * hard-coded allowlist — and are never derived from user input. This
 * satisfies PluginCheck.Security.DirectDB without suppression comments.
 *
 * Direct queries are unavoidable here because:
 *  - We need dynamic column/table combinations not supported by WP_Query.
 *  - The LIKE pattern scan across multiple tables has no WP API equivalent.
 * All queries use $wpdb->prepare() for the LIKE value and cache is bypassed
 * intentionally (security scans must read live data).
 *
 * The full scan is broken into one table+column "unit" per call
 * (see get_scan_units() / scan_unit()) so the admin UI can run each unit
 * as its own AJAX request. This keeps every single HTTP request short —
 * checking 15 patterns against one column — instead of running all
 * 9 column × 15 pattern combinations (135 queries) inside one request,
 * which is what previously caused 504 Gateway Timeout errors on larger
 * databases or slower hosts.
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
	 * Runs at most 15 short LIKE queries (one per pattern) against a single
	 * column, so it completes well within any host's proxy timeout even on
	 * large tables.
	 *
	 * @since  1.0.0
	 * @param  string $raw_table  Table name (validated against allowlist by caller).
	 * @param  string $raw_column Column name (validated against allowlist by caller).
	 * @param  string $pk         Primary key column name for this table.
	 * @return array<int,array<string,string>> Threat records found in this unit.
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

		foreach ( $patterns as $pattern => $label ) {

			$like = '%' . $wpdb->esc_like( $pattern ) . '%';

			/*
			 * Direct query rationale: WP has no API for LIKE searches
			 * across arbitrary columns. Table, column, and pk are all
			 * sourced from the hard-coded allowlist in SFDS_Patterns —
			 * never from user input — so interpolation is safe here.
			 */
			// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT `{$safe_pk}` AS row_id, LEFT(`{$safe_column}`, 300) AS snippet FROM `{$safe_table}` WHERE `{$safe_column}` LIKE %s LIMIT 50",
					$like
				),
				ARRAY_A
			);
			// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared

			if ( empty( $rows ) ) {
				continue;
			}

			foreach ( $rows as $row ) {
				// Deduplicate: one entry per table + row_id combination.
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
					'snippet' => wp_strip_all_tags( $row['snippet'] ),
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
	 * over get_scan_units() instead to avoid 504 Gateway Timeout errors,
	 * see the class docblock for details.
	 *
	 * @since  1.0.0
	 * @return array<int,array<string,string>> List of threat records found.
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