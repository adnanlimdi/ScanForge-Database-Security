<?php
/**
 * Admin interface.
 *
 * @package ScanForge_DB_Security
 * @since   1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class SFDS_Admin
 *
 * Registers the admin menu page and handles all AJAX requests.
 *
 * @since 1.0.0
 */
class SFDS_Admin {

	/**
	 * Attach all WordPress hooks.
	 *
	 * @since 1.0.0
	 */
	public function init() {
		add_action( 'admin_menu',                  array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts',       array( $this, 'enqueue_assets' ) );
		add_action( 'wp_ajax_sfds_scan',           array( $this, 'ajax_scan' ) );
		add_action( 'wp_ajax_sfds_get_scan_units', array( $this, 'ajax_get_scan_units' ) );
		add_action( 'wp_ajax_sfds_scan_unit',      array( $this, 'ajax_scan_unit' ) );
		add_action( 'wp_ajax_sfds_clean_row',      array( $this, 'ajax_clean_row' ) );
		add_action( 'wp_ajax_sfds_clean_all',      array( $this, 'ajax_clean_all' ) );
		add_action( 'wp_ajax_sfds_get_raw',        array( $this, 'ajax_get_raw' ) );
		add_action( 'wp_ajax_sfds_db_download',    array( $this, 'ajax_db_download' ) );
	}

	/**
	 * Register the admin menu item.
	 *
	 * @since 1.0.0
	 */
	public function register_menu() {
		add_menu_page(
			__( 'ScanForge Database Security', 'scanforge-db-security' ),
			__( 'ScanForge Database Security', 'scanforge-db-security' ),
			'manage_options',
			'scanforge-db-security',
			array( $this, 'render_page' ),
			'dashicons-shield-alt',
			99
		);
	}

	/**
	 * Enqueue admin styles and scripts.
	 *
	 * @since 1.0.0
	 * @param string $hook Current admin page hook.
	 */
	public function enqueue_assets( $hook ) {
		if ( 'toplevel_page_scanforge-db-security' !== $hook ) {
			return;
		}

		wp_enqueue_style(
			'sfds-admin',
			SFDS_PLUGIN_URL . 'assets/admin.css',
			array(),
			SFDS_VERSION
		);

		wp_enqueue_script(
			'sfds-admin',
			SFDS_PLUGIN_URL . 'assets/admin.js',
			array( 'jquery' ),
			SFDS_VERSION,
			true
		);

		wp_localize_script(
			'sfds-admin',
			'sfdsData',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'sfds_nonce' ),
				'i18n'    => array(
					'scanning'        => __( 'Scanning database tables for malicious patterns…', 'scanforge-db-security' ),
					'scanningUnit'    => __( 'Scanning', 'scanforge-db-security' ),
					'scanLabel'       => __( 'Scan Database', 'scanforge-db-security' ),
					'resumeScan'      => __( 'Resume Scan', 'scanforge-db-security' ),
					'scanStopped'     => __( 'Scan stopped at unit', 'scanforge-db-security' ),
					'resumeHint'      => __( 'Click "Resume Scan" to continue from where it stopped.', 'scanforge-db-security' ),
					'retrying'        => __( 'Retrying', 'scanforge-db-security' ),
					'noThreats'       => __( 'No threats found. Your database looks clean!', 'scanforge-db-security' ),
					'threatsFound'    => __( 'threat(s) found. Review below and clean.', 'scanforge-db-security' ),
					'cleaning'        => __( 'Cleaning all threats…', 'scanforge-db-security' ),
					'cleanDone'       => __( 'Cleaned', 'scanforge-db-security' ),
					'cleanFailed'     => __( 'failed', 'scanforge-db-security' ),
					'confirmClean'    => __( 'This will clean ALL threats. Make sure you have a backup first. Continue?', 'scanforge-db-security' ),
					'rowCleaned'      => __( 'Cleaned row', 'scanforge-db-security' ),
					'rowFailed'       => __( 'Failed to clean row', 'scanforge-db-security' ),
					'done'            => __( '✓ Done', 'scanforge-db-security' ),
					'clean'           => __( 'Clean', 'scanforge-db-security' ),
					'noChange'        => __( 'Content unchanged — may be double-serialized. Edit manually in phpMyAdmin.', 'scanforge-db-security' ),
					'manualClean'     => __( 'Could not clean automatically. Please clean this row manually in phpMyAdmin.', 'scanforge-db-security' ),
					'someFailedManual'=> __( 'could not be auto-cleaned — please clean those manually in phpMyAdmin.', 'scanforge-db-security' ),
					'rescanPrompt'    => __( 'Click Scan Database again to confirm everything is clean.', 'scanforge-db-security' ),
					'dbGenerating'    => __( 'Generating backup… this may take a moment.', 'scanforge-db-security' ),
					'dbDone'          => __( 'Backup ready — download started.', 'scanforge-db-security' ),
					'dbError'         => __( 'Backup failed. Please try again.', 'scanforge-db-security' ),
					'requestTimeout'  => __( 'Request timed out. Your server may be slow — try again, it will resume where it left off.', 'scanforge-db-security' ),
					'serverError'     => __( 'Server error occurred. Check your error log or try again.', 'scanforge-db-security' ),
					'connectionLost'  => __( 'Connection lost. Check your internet connection and try again.', 'scanforge-db-security' ),
					'confirmDownload' => __( 'Generate a full SQL backup of your database. Continue?', 'scanforge-db-security' ),
					'ready'           => __( 'Ready to scan. Click "Scan Database" to begin.', 'scanforge-db-security' ),
				),
			)
		);
	}

	// ── AJAX: Scan ───────────────────────────────────────────

	/**
	 * AJAX handler — return the list of scannable units.
	 *
	 * The UI calls this first, then loops ajax_scan_unit() once per unit.
	 * Each unit is one table+column pair, so no single request runs more
	 * than 15 pattern checks — this is what prevents 504 Gateway Timeout
	 * errors on large databases.
	 *
	 * @since 1.0.0
	 */
	public function ajax_get_scan_units() {
		check_ajax_referer( 'sfds_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized.', 'scanforge-db-security' ) ), 403 );
		}

		$scanner = new SFDS_Scanner();
		$units   = $scanner->get_scan_units();

		wp_send_json_success(
			array(
				'units' => $units,
				'count' => count( $units ),
			)
		);
	}

	/**
	 * AJAX handler — scan a single table+column unit.
	 *
	 * @since 1.0.0
	 */
	public function ajax_scan_unit() {
		check_ajax_referer( 'sfds_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized.', 'scanforge-db-security' ) ), 403 );
		}

		$raw_table  = isset( $_POST['table'] )  ? sanitize_text_field( wp_unslash( $_POST['table'] ) )  : '';
		$raw_column = isset( $_POST['column'] ) ? sanitize_text_field( wp_unslash( $_POST['column'] ) ) : '';

		// Validate against the hard-coded allowlist before running any query.
		$table  = SFDS_Patterns::validate_table( $raw_table );
		$column = SFDS_Patterns::validate_column( $raw_table, $raw_column );
		$pk     = SFDS_Patterns::get_primary_key( $raw_table );

		if ( ! $table || ! $column || ! $pk ) {
			wp_send_json_error( array( 'message' => __( 'Invalid or disallowed parameters.', 'scanforge-db-security' ) ) );
		}

		$scanner = new SFDS_Scanner();
		$results = $scanner->scan_unit( $table, $column, $pk );

		wp_send_json_success(
			array(
				'results' => $results,
				'count'   => count( $results ),
			)
		);
	}

	/**
	 * AJAX handler — scan the entire database in one request.
	 *
	 * Kept for backward compatibility. The UI no longer calls this directly
	 * for the main Scan Database button — it loops ajax_scan_unit() instead
	 * to avoid 504 Gateway Timeout errors on larger databases. See the
	 * SFDS_Scanner class docblock for details.
	 *
	 * @since 1.0.0
	 */
	public function ajax_scan() {
		check_ajax_referer( 'sfds_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized.', 'scanforge-db-security' ) ), 403 );
		}

		if ( function_exists( 'set_time_limit' ) ) {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_set_time_limit
			@set_time_limit( 0 );
		}

		$scanner = new SFDS_Scanner();
		$results = $scanner->scan();

		wp_send_json_success(
			array(
				'results' => $results,
				'count'   => count( $results ),
			)
		);
	}

	// ── AJAX: Clean single row ───────────────────────────────

	/**
	 * AJAX handler — clean a single database row.
	 *
	 * @since 1.0.0
	 */
	public function ajax_clean_row() {
		check_ajax_referer( 'sfds_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized.', 'scanforge-db-security' ) ), 403 );
		}

		// 1. Sanitize raw POST values.
		$raw_table  = isset( $_POST['table'] )  ? sanitize_text_field( wp_unslash( $_POST['table'] ) )  : '';
		$raw_column = isset( $_POST['column'] ) ? sanitize_text_field( wp_unslash( $_POST['column'] ) ) : '';
		$row_id     = isset( $_POST['row_id'] ) ? absint( $_POST['row_id'] )                            : 0;

		// 2. Validate identifiers against hard-coded allowlist only.
		$validated_table  = SFDS_Patterns::validate_table( $raw_table );
		$validated_column = SFDS_Patterns::validate_column( $raw_table, $raw_column );
		$validated_pk     = SFDS_Patterns::get_primary_key( $raw_table );

		if ( ! $validated_table || ! $validated_column || ! $validated_pk || ! $row_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid or disallowed parameters.', 'scanforge-db-security' ) ) );
		}

		// esc_sql() applied at assignment so plugin checker recognises safe escaping.
		$table  = esc_sql( $validated_table );
		$column = esc_sql( $validated_column );
		$pk     = esc_sql( $validated_pk );



		$cleaner = new SFDS_Cleaner();
		$success = $cleaner->clean_row( $table, $column, $pk, $row_id );

		wp_send_json_success( array( 'cleaned' => $success ) );
	}

	// ── AJAX: Clean all ──────────────────────────────────────

	/**
	 * AJAX handler — clean all threats found by a fresh scan.
	 *
	 * Kept for backward compatibility but no longer used by the UI for large
	 * sites — JS now loops over individual sfds_clean_row calls instead to
	 * avoid gateway timeouts on databases with many threats. This endpoint
	 * still works for small scans triggered programmatically.
	 *
	 * @since 1.0.0
	 */
	public function ajax_clean_all() {
		check_ajax_referer( 'sfds_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized.', 'scanforge-db-security' ) ), 403 );
		}

		// Raise time limit defensively; many hosts still cap this via nginx
		// regardless, which is why the UI no longer relies on this endpoint
		// for bulk cleaning — see sfds_clean_row for the batched approach.
		if ( function_exists( 'set_time_limit' ) ) {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_set_time_limit
			@set_time_limit( 0 );
		}

		$scanner = new SFDS_Scanner();
		$threats = $scanner->scan();

		$cleaner = new SFDS_Cleaner();
		$result  = $cleaner->clean_all( $threats );

		wp_send_json_success( $result );
	}

	// ── AJAX: Get raw value ──────────────────────────────────

	/**
	 * AJAX handler — return raw DB value for manual inspection.
	 *
	 * @since 1.0.0
	 */
	public function ajax_get_raw() {
		check_ajax_referer( 'sfds_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized.', 'scanforge-db-security' ) ), 403 );
		}

		global $wpdb;

		$raw_table  = isset( $_POST['table'] )  ? sanitize_text_field( wp_unslash( $_POST['table'] ) )  : '';
		$raw_column = isset( $_POST['column'] ) ? sanitize_text_field( wp_unslash( $_POST['column'] ) ) : '';
		$row_id     = isset( $_POST['row_id'] ) ? absint( $_POST['row_id'] )                            : 0;

		$validated_table  = SFDS_Patterns::validate_table( $raw_table );
		$validated_column = SFDS_Patterns::validate_column( $raw_table, $raw_column );
		$validated_pk     = SFDS_Patterns::get_primary_key( $raw_table );

		if ( ! $validated_table || ! $validated_column || ! $validated_pk || ! $row_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid or disallowed parameters.', 'scanforge-db-security' ) ) );
		}

		// esc_sql() applied at assignment so plugin checker recognises safe escaping.
		$table  = esc_sql( $validated_table );
		$column = esc_sql( $validated_column );
		$pk     = esc_sql( $validated_pk );



		// Identifiers ($column, $table, $pk) are allowlist-validated via SFDS_Patterns
		// and never derived from user input. $wpdb->prepare() cannot use placeholders
		// for SQL identifiers — interpolation of validated identifiers is correct here.
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT `{$column}` FROM `{$table}` WHERE `{$pk}` = %d",
				$row_id
			),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		if ( empty( $row ) ) {
			wp_send_json_error( array( 'message' => __( 'Row not found.', 'scanforge-db-security' ) ) );
		}

		wp_send_json_success( array( 'raw' => $row[ $column ] ) );
	}

	// ── AJAX: DB download ────────────────────────────────────

	/**
	 * AJAX handler — build a SQL dump and return it as a base64 JSON payload.
	 *
	 * Returning the dump via wp_send_json_success() avoids header-conflict
	 * issues caused by WP output buffering when streaming a direct download.
	 * The JS side decodes the base64 string and triggers a Blob download.
	 *
	 * @since 1.0.0
	 */
	public function ajax_db_download() {
		check_ajax_referer( 'sfds_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized.', 'scanforge-db-security' ) ), 403 );
		}

		global $wpdb;

		// Only two accepted values — anything else defaults to 'all'.
		$raw_scope = isset( $_POST['scope'] ) ? sanitize_text_field( wp_unslash( $_POST['scope'] ) ) : 'all';
		$scope     = in_array( $raw_scope, array( 'all', 'security' ), true ) ? $raw_scope : 'all';

		// Determine tables to export.
		if ( 'security' === $scope ) {
			$tables = array_keys( SFDS_Patterns::get_scan_targets() );
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$all    = $wpdb->get_results( 'SHOW TABLES', ARRAY_N );
			$tables = $all ? array_column( $all, 0 ) : array();
		}

		if ( empty( $tables ) ) {
			wp_send_json_error( array( 'message' => __( 'No tables found to export.', 'scanforge-db-security' ) ) );
		}

		// Build the SQL dump in memory.
		$sql  = "-- ScanForge Database Security Backup\n";
		$sql .= '-- Generated : ' . gmdate( 'Y-m-d H:i:s' ) . " UTC\n";
		$sql .= '-- Database  : ' . sanitize_text_field( DB_NAME ) . "\n";
		$sql .= "-- Tables    : " . count( $tables ) . "\n";
		$sql .= "-- -------------------------------------------\n\n";
		$sql .= "SET FOREIGN_KEY_CHECKS=0;\n";
		$sql .= "SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\n\n";

		foreach ( $tables as $table ) {
			// esc_sql() escapes the table name for safe interpolation.
			$safe_table = esc_sql( $table );

			$sql .= "\n-- Table: `{$safe_table}`\n";
			$sql .= "DROP TABLE IF EXISTS `{$safe_table}`;\n";

			// SHOW CREATE TABLE: no WP API equivalent. $safe_table is esc_sql()-escaped
			// and sourced from the DB server itself (SHOW TABLES) or our allowlist —
			// never from user input. SchemaChange is a read-only introspection query.
			// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.SchemaChange
			$create = $wpdb->get_row( "SHOW CREATE TABLE `{$safe_table}`", ARRAY_N );
			// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.SchemaChange
			if ( $create && isset( $create[1] ) ) {
				$sql .= $create[1] . ";\n\n";
			}

			// Export rows in chunks to stay within memory limits.
			$offset     = 0;
			$chunk_size = 200;

			do {
				// $safe_table is esc_sql()-escaped; $chunk_size and $offset are integers via %d.
				// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$rows = $wpdb->get_results(
					$wpdb->prepare( "SELECT * FROM `{$safe_table}` LIMIT %d OFFSET %d", $chunk_size, $offset ),
					ARRAY_A
				);
				// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared

				if ( empty( $rows ) ) {
					break;
				}

				$col_list = '`' . implode( '`, `', array_keys( $rows[0] ) ) . '`';

				foreach ( $rows as $row ) {
					$values = array();
					foreach ( $row as $cell ) {
						if ( null === $cell ) {
							$values[] = 'NULL';
						} else {
							// addslashes is correct here — we are building SQL text,
							// not outputting HTML. esc_sql() would double-escape.
							$values[] = "'" . addslashes( $cell ) . "'";
						}
					}
					$sql .= 'INSERT INTO `' . $safe_table . '` (' . $col_list . ') VALUES (' . implode( ', ', $values ) . ");\n";
				}

				$offset += $chunk_size;

			} while ( count( $rows ) === $chunk_size );

			$sql .= "\n";
		}

		$sql .= "SET FOREIGN_KEY_CHECKS=1;\n";
		$sql .= "-- End of backup\n";

		// Return as base64 so JSON transport is safe with binary/special chars.
		wp_send_json_success(
			array(
				// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
				'sql'      => base64_encode( $sql ),
				'filename' => 'db-backup-' . gmdate( 'Y-m-d-His' ) . '.sql',
			)
		);
	}

	// ── Render page ──────────────────────────────────────────

	/**
	 * Render the admin page HTML.
	 *
	 * @since 1.0.0
	 */
	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		?>
		<div class="wrap sfds-wrap">

			<!-- Header -->
			<div class="sfds-header">
				<div class="sfds-header-icon">
					<span class="dashicons dashicons-shield-alt"></span>
				</div>
				<div class="sfds-header-text">
					<h1><?php esc_html_e( 'ScanForge Database Security', 'scanforge-db-security' ); ?></h1>
					<span class="sfds-subtitle">
						<?php esc_html_e( 'wp_posts · wp_options · wp_postmeta · wp_usermeta · wp_comments', 'scanforge-db-security' ); ?>
					</span>
				</div>
			</div>

			<!-- Warning banner -->
			<div class="sfds-banner">
				<span class="dashicons dashicons-warning"></span>
				<?php esc_html_e( 'Download a database backup before running Clean All.', 'scanforge-db-security' ); ?>
			</div>

			<!-- Toolbar -->
			<div class="sfds-toolbar">
				<button id="sfds-btn-scan" class="sfds-btn sfds-btn-primary">
					<span class="dashicons dashicons-search"></span>
					<span id="sfds-btn-scan-label"><?php esc_html_e( 'Scan Database', 'scanforge-db-security' ); ?></span>
				</button>
				<button id="sfds-btn-clean-all" class="sfds-btn sfds-btn-danger" disabled>
					<span class="dashicons dashicons-trash"></span>
					<?php esc_html_e( 'Clean All Threats', 'scanforge-db-security' ); ?>
				</button>
				<button id="sfds-btn-export" class="sfds-btn sfds-btn-success" style="display:none">
					<span class="dashicons dashicons-media-spreadsheet"></span>
					<?php esc_html_e( 'Export CSV', 'scanforge-db-security' ); ?>
				</button>
			</div>

			<!-- Status bar -->
			<div id="sfds-status" class="sfds-status">
				<span class="sfds-status-dot"></span>
				<span id="sfds-status-text"><?php esc_html_e( 'Ready — click Scan Database to begin.', 'scanforge-db-security' ); ?></span>
			</div>

			<!-- Stat cards -->
			<div class="sfds-stats">
				<div class="sfds-stat sfds-stat--scanned">
					<div class="sfds-stat-icon">
						<span class="dashicons dashicons-database-view"></span>
					</div>
					<div class="sfds-stat-body">
						<span id="sfds-stat-scanned" class="sfds-stat-number">&mdash;</span>
						<span class="sfds-stat-label"><?php esc_html_e( 'Tables Scanned', 'scanforge-db-security' ); ?></span>
					</div>
				</div>
				<div class="sfds-stat sfds-stat--threats">
					<div class="sfds-stat-icon">
						<span class="dashicons dashicons-warning"></span>
					</div>
					<div class="sfds-stat-body">
						<span id="sfds-stat-threats" class="sfds-stat-number">&mdash;</span>
						<span class="sfds-stat-label"><?php esc_html_e( 'Threats Found', 'scanforge-db-security' ); ?></span>
					</div>
				</div>
				<div class="sfds-stat sfds-stat--cleaned">
					<div class="sfds-stat-icon">
						<span class="dashicons dashicons-yes-alt"></span>
					</div>
					<div class="sfds-stat-body">
						<span id="sfds-stat-cleaned" class="sfds-stat-number">&mdash;</span>
						<span class="sfds-stat-label"><?php esc_html_e( 'Threats Cleaned', 'scanforge-db-security' ); ?></span>
					</div>
				</div>
			</div>

			<!-- Results panel -->
			<div id="sfds-results-wrap"></div>

			<hr class="sfds-divider">

			<!-- Backup section -->
			<div class="sfds-backup">
				<div class="sfds-backup-header">
					<span class="dashicons dashicons-database-export"></span>
					<h3><?php esc_html_e( 'Download Database Backup', 'scanforge-db-security' ); ?></h3>
				</div>
				<p><?php esc_html_e( 'Generate and download an SQL backup before running any clean operations.', 'scanforge-db-security' ); ?></p>

				<div class="sfds-backup-form">
					<label for="sfds-db-scope" class="screen-reader-text">
						<?php esc_html_e( 'Tables to export', 'scanforge-db-security' ); ?>
					</label>
					<select id="sfds-db-scope">
						<option value="all"><?php esc_html_e( 'All Tables (Full Backup)', 'scanforge-db-security' ); ?></option>
						<option value="security"><?php esc_html_e( 'Scanned Tables Only', 'scanforge-db-security' ); ?></option>
					</select>
					<button id="sfds-btn-db-download" class="sfds-btn sfds-btn-db">
						<span class="dashicons dashicons-download"></span>
						<?php esc_html_e( 'Download Backup (.sql)', 'scanforge-db-security' ); ?>
					</button>
				</div>

				<div id="sfds-db-progress" class="sfds-db-progress">
					<span class="dashicons dashicons-update sfds-spin"></span>
					<span id="sfds-db-progress-text"></span>
				</div>
			</div>

		</div>
		<?php
	}
}
