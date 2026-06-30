/**
 * ScanForge Database Security — Admin JavaScript
 *
 * @package ScanForge_DB_Security
 * @since   1.0.0
 */

/* global sfdsData */
( function ( $ ) {
	'use strict';

	var scanResults  = [];
	var cleanedCount = 0;

	var $status     = $( '#sfds-status' );
	var $btnScan    = $( '#sfds-btn-scan' );
	var $btnClean   = $( '#sfds-btn-clean-all' );
	var $btnExport  = $( '#sfds-btn-export' );
	var $btnDbDl    = $( '#sfds-btn-db-download' );
	var $dbProgress = $( '#sfds-db-progress' );
	var $dbProgText = $( '#sfds-db-progress-text' );
	var $wrap       = $( '#sfds-results-wrap' );

	// ── Helpers ──────────────────────────────────────────────

	/**
	 * Update the status bar text and colour modifier.
	 *
	 * @param {string} message  Text to display.
	 * @param {string} modifier CSS class: is-scanning | is-found | is-clean | is-cleaning
	 */
	function setStatus( message, modifier ) {
		$status
			.removeClass( 'is-scanning is-found is-clean is-cleaning' )
			.addClass( modifier || '' );
		$( '#sfds-status-text' ).text( message );
	}

	/**
	 * Update a stat card value by element ID.
	 *
	 * @param {string} id  Element ID without #.
	 * @param {mixed}  val Value to display.
	 */
	function setStat( id, val ) {
		$( '#' + id ).text( val );
	}

	/**
	 * Escape HTML special characters to prevent XSS when injecting into DOM.
	 *
	 * @param  {string} str Raw string.
	 * @return {string}     HTML-escaped string.
	 */
	function escHtml( str ) {
		return String( str )
			.replace( /&/g,  '&amp;'  )
			.replace( /</g,  '&lt;'   )
			.replace( />/g,  '&gt;'   )
			.replace( /"/g,  '&quot;' )
			.replace( /'/g,  '&#039;' );
	}

	/**
	 * Send an AJAX POST and call cb( response.data ) on success.
	 *
	 * Each call now has its own short timeout. Combined with the unit-by-unit
	 * scan/clean loops, a single slow request fails fast with a clear message
	 * instead of the browser hanging until a generic, unhelpful network error.
	 *
	 * @param {string}   action WordPress AJAX action slug.
	 * @param {Object}   data   Extra POST fields.
	 * @param {Function} cb     Success callback receives response.data.
	 */
	function doAjax( action, data, cb ) {
		$.ajax( {
			url:      sfdsData.ajaxUrl,
			method:   'POST',
			data:     $.extend( { action: action, nonce: sfdsData.nonce }, data ),
			dataType: 'json',
			timeout:  30000 // 30s per request — each unit/row is small, so this is generous.
		} )
			.done( function ( response ) {
				if ( response && response.success ) {
					cb( response.data );
				} else {
					var msg = ( response && response.data && response.data.message )
						? response.data.message
						: sfdsData.i18n.dbError;
					setStatus( msg, '' );
				}
			} )
			.fail( function ( xhr, textStatus ) {
				var msg;
				if ( 'timeout' === textStatus ) {
					msg = sfdsData.i18n.requestTimeout;
				} else if ( xhr.status >= 500 ) {
					msg = sfdsData.i18n.serverError + ' (HTTP ' + xhr.status + ')';
				} else if ( 0 === xhr.status ) {
					msg = sfdsData.i18n.connectionLost;
				} else {
					msg = sfdsData.i18n.dbError + ' (' + textStatus + ')';
				}
				setStatus( msg, '' );
			} );
	}

	/**
	 * Trigger a file download from a string using a Blob.
	 *
	 * @param {string} content  File content string.
	 * @param {string} filename Suggested file name.
	 * @param {string} mimeType MIME type of the file.
	 */
	function triggerDownload( content, filename, mimeType ) {
		var blob = new Blob( [ content ], { type: mimeType } );
		var url  = URL.createObjectURL( blob );
		var a    = document.createElement( 'a' );

		a.href     = url;
		a.download = filename;
		a.style.display = 'none';

		document.body.appendChild( a );
		a.click();

		// Clean up after a short delay.
		setTimeout( function () {
			document.body.removeChild( a );
			URL.revokeObjectURL( url );
		}, 200 );
	}

	// ── Render results table ─────────────────────────────────

	/**
	 * Render the threat results table into #sfds-results-wrap.
	 *
	 * @param {Array} results Array of threat objects from the server.
	 */
	function renderResults( results ) {
		if ( ! results.length ) {
			$wrap.html(
				'<div class="sfds-empty">' +
					'<span class="dashicons dashicons-yes-alt"></span>' +
					'<p>' + escHtml( sfdsData.i18n.noThreats ) + '</p>' +
					'<small>scan complete — no malicious patterns detected</small>' +
				'</div>'
			);
			return;
		}

		var html = '<table class="sfds-results widefat">';
		html    += '<colgroup>';
		html    += '<col style="width:42px"><col style="width:170px"><col style="width:130px">';
		html    += '<col style="width:80px"><col style="width:210px"><col><col style="width:90px">';
		html    += '</colgroup>';
		html    += '<thead><tr>';
		html    += '<th>#</th><th>' + escHtml( 'Table' ) + '</th><th>' + escHtml( 'Column' ) + '</th>';
		html    += '<th>' + escHtml( 'Row ID' ) + '</th><th>' + escHtml( 'Threat' ) + '</th>';
		html    += '<th>' + escHtml( 'Snippet' ) + '</th><th>' + escHtml( 'Action' ) + '</th>';
		html    += '</tr></thead><tbody>';

		$.each( results, function ( i, r ) {
			html += '<tr id="sfds-row-' + parseInt( i, 10 ) + '" data-index="' + parseInt( i, 10 ) + '">';
			html += '<td style="color:#646970">' + ( i + 1 ) + '</td>';
			html += '<td><span class="sfds-badge sfds-badge-table">' + escHtml( r.table ) + '</span></td>';
			html += '<td><code style="font-size:12px">' + escHtml( r.column ) + '</code></td>';
			html += '<td><strong>' + escHtml( String( r.row_id ) ) + '</strong></td>';
			html += '<td><span class="sfds-badge sfds-badge-threat">' + escHtml( r.label ) + '</span></td>';
			html += '<td><span class="sfds-snippet" title="' + escHtml( r.snippet ) + '">' + escHtml( r.snippet ) + '</span></td>';
			html += '<td><button class="button button-small sfds-row-btn" data-index="' + parseInt( i, 10 ) + '">';
			html += escHtml( sfdsData.i18n.clean ) + '</button></td>';
			html += '</tr>';
		} );

		html += '</tbody></table>';
		$wrap.html( html );
	}

	// ── Scan (batched, one table+column unit per request) ────

	/**
	 * Scan every unit (table+column pair) one at a time.
	 *
	 * Looping in JS instead of scanning everything in a single PHP request
	 * avoids 504 Gateway Timeout / generic "Request error" failures on hosts
	 * with short proxy timeouts — each request only checks 15 patterns
	 * against one column, however many units exist (currently 9).
	 *
	 * @param {Array}  units     Array of { table, column, pk } unit objects.
	 * @param {number} idx       Current index in the loop.
	 * @param {Array}  collected Threats collected so far across all units.
	 */
	function scanUnitsSequentially( units, idx, collected ) {
		if ( idx >= units.length ) {
			// Done — finalise and render.
			$btnScan.prop( 'disabled', false )
				.find( '.dashicons' )
				.removeClass( 'sfds-spinner dashicons-update' )
				.addClass( 'dashicons-search' );

			scanResults = collected;
			var count   = collected.length;

			setStat( 'sfds-stat-threats', count );

			if ( 0 === count ) {
				setStatus( '✓ ' + sfdsData.i18n.noThreats, 'is-clean' );
				$btnClean.prop( 'disabled', true );
				$btnExport.hide();
			} else {
				setStatus( '⚠ ' + count + ' ' + sfdsData.i18n.threatsFound, 'is-found' );
				$btnClean.prop( 'disabled', false );
				$btnExport.show();
			}

			renderResults( scanResults );
			return;
		}

		var unit = units[ idx ];

		setStatus(
			sfdsData.i18n.scanningUnit + ' ' + escHtml( unit.table ) + '.' + escHtml( unit.column ) +
			' (' + ( idx + 1 ) + ' / ' + units.length + ')',
			'is-scanning'
		);

		doAjax(
			'sfds_scan_unit',
			{ table: unit.table, column: unit.column },
			function ( data ) {
				var merged = collected.concat( data.results );
				// Keep the live count updating as we go, not just at the end.
				setStat( 'sfds-stat-threats', merged.length );
				scanUnitsSequentially( units, idx + 1, merged );
			}
		);
	}

	$btnScan.on( 'click', function () {
		$btnScan.prop( 'disabled', true )
			.find( '.dashicons' )
			.removeClass( 'dashicons-search' )
			.addClass( 'sfds-spinner dashicons-update' );

		setStatus( sfdsData.i18n.scanning, 'is-scanning' );
		setStat( 'sfds-stat-scanned', '5' );
		setStat( 'sfds-stat-threats', '…' );
		setStat( 'sfds-stat-cleaned', cleanedCount || '0' );
		$wrap.html( '' );

		// First fetch the list of units, then scan them one at a time.
		doAjax( 'sfds_get_scan_units', {}, function ( data ) {
			if ( ! data.units || ! data.units.length ) {
				$btnScan.prop( 'disabled', false )
					.find( '.dashicons' )
					.removeClass( 'sfds-spinner dashicons-update' )
					.addClass( 'dashicons-search' );
				setStatus( sfdsData.i18n.dbError, '' );
				return;
			}
			scanUnitsSequentially( data.units, 0, [] );
		} );
	} );

	// ── Clean single row (delegated) ─────────────────────────

	$wrap.on( 'click', '.sfds-row-btn', function () {
		var $btn  = $( this );
		var index = parseInt( $btn.data( 'index' ), 10 );
		var r     = scanResults[ index ];

		if ( ! r ) {
			return;
		}

		$btn.prop( 'disabled', true ).text( '…' );

		doAjax(
			'sfds_clean_row',
			{ table: r.table, column: r.column, pk: r.pk, row_id: r.row_id },
			function ( data ) {
				if ( data.cleaned ) {
					$( '#sfds-row-' + index ).addClass( 'sfds-row-cleaned' );
					$btn.text( sfdsData.i18n.done ).addClass( 'is-done' );
					cleanedCount++;
					setStat( 'sfds-stat-cleaned', cleanedCount );
					setStatus( sfdsData.i18n.rowCleaned + ' #' + escHtml( String( r.row_id ) ) + ' in ' + escHtml( r.table ), 'is-clean' );
				} else {
					// Auto-clean failed — flag the row and point to manual cleaning.
					$( '#sfds-row-' + index ).addClass( 'sfds-row-manual' );
					$btn.prop( 'disabled', false )
						.text( sfdsData.i18n.manualClean )
						.addClass( 'is-manual' )
						.attr( 'title', sfdsData.i18n.manualClean );
					setStatus( sfdsData.i18n.rowFailed + ' #' + escHtml( String( r.row_id ) ) + ' — ' + sfdsData.i18n.manualClean, 'is-found' );
				}
			}
		);
	} );

	// ── Clean all (sequential, one row per request) ──────────

	/**
	 * Clean every threat in scanResults one at a time.
	 *
	 * Looping in JS instead of cleaning everything in a single PHP request
	 * avoids 504 Gateway Timeout errors on hosts with short proxy timeouts
	 * (nginx commonly defaults to 60s) — each request only cleans one row,
	 * however many threats exist.
	 *
	 * @param {Array}    items    Array of threat objects to clean.
	 * @param {number}   idx      Current index in the loop.
	 * @param {number}   cleaned  Running count of successful cleans.
	 * @param {number}   failed   Running count of failed cleans.
	 */
	function cleanAllSequentially( items, idx, cleaned, failed ) {
		if ( idx >= items.length ) {
			// Done — show final tally. Scanning is no longer auto-triggered here:
			// since Scan itself now loops over 9 units sequentially, silently
			// re-running it straight after Clean All looked like an unexplained
			// second operation. The admin can click Scan again if they want to
			// confirm the database is clean.
			$btnClean.prop( 'disabled', false ).find( '.dashicons' ).removeClass( 'sfds-spinner' );
			cleanedCount = cleaned;
			setStat( 'sfds-stat-cleaned', cleanedCount );

			var summary = sfdsData.i18n.cleanDone + ': ' + cleaned + '  ' +
				sfdsData.i18n.cleanFailed + ': ' + failed;

			if ( failed > 0 ) {
				// Some rows couldn't be auto-cleaned — point the admin to phpMyAdmin.
				summary += ' — ' + failed + ' ' + sfdsData.i18n.someFailedManual;
				setStatus( summary, 'is-found' );
			} else {
				summary += ' — ' + sfdsData.i18n.rescanPrompt;
				setStatus( summary, 'is-clean' );
			}

			return;
		}

		var r = items[ idx ];

		setStatus(
			sfdsData.i18n.cleaning + ' (' + ( idx + 1 ) + ' / ' + items.length + ')',
			'is-cleaning'
		);

		doAjax(
			'sfds_clean_row',
			{ table: r.table, column: r.column, pk: r.pk, row_id: r.row_id },
			function ( data ) {
				var $row = $( '#sfds-row-' + idx );

				if ( data.cleaned ) {
					$row.addClass( 'sfds-row-cleaned' );
					$row.find( '.sfds-row-btn' ).text( sfdsData.i18n.done ).addClass( 'is-done' ).prop( 'disabled', true );
					cleaned++;
				} else {
					// Mark the row so the admin can spot it and clean manually.
					$row.addClass( 'sfds-row-manual' );
					$row.find( '.sfds-row-btn' )
						.text( sfdsData.i18n.manualClean )
						.addClass( 'is-manual' )
						.attr( 'title', sfdsData.i18n.manualClean )
						.prop( 'disabled', false );
					failed++;
				}

				setStat( 'sfds-stat-cleaned', cleaned );

				// Continue to the next item regardless of success/failure.
				cleanAllSequentially( items, idx + 1, cleaned, failed );
			}
		);
	}

	$btnClean.on( 'click', function () {
		if ( ! scanResults.length ) {
			return;
		}

		if ( ! window.confirm( sfdsData.i18n.confirmClean ) ) {
			return;
		}

		$btnClean.prop( 'disabled', true )
			.find( '.dashicons' )
			.addClass( 'sfds-spinner' );

		// Loop sequentially over every threat from the row index 0.
		cleanAllSequentially( scanResults, 0, 0, 0 );
	} );

	// ── Export CSV ───────────────────────────────────────────

	$btnExport.on( 'click', function () {
		if ( ! scanResults.length ) {
			return;
		}

		var csv  = 'Table,Column,Row ID,Threat,Snippet\n';
		var date = new Date().toISOString().slice( 0, 10 );

		$.each( scanResults, function ( i, r ) {
			// Wrap every field in quotes; escape internal quotes by doubling them.
			csv += '"' + String( r.table   ).replace( /"/g, '""' ) + '",' +
			       '"' + String( r.column  ).replace( /"/g, '""' ) + '",' +
			       '"' + String( r.row_id  ).replace( /"/g, '""' ) + '",' +
			       '"' + String( r.label   ).replace( /"/g, '""' ) + '",' +
			       '"' + String( r.snippet ).replace( /"/g, '""' ) + '"\n';
		} );

		triggerDownload( csv, 'db-security-scan-' + date + '.csv', 'text/csv;charset=utf-8;' );
	} );

	// ── DB Download ──────────────────────────────────────────

	$btnDbDl.on( 'click', function () {
		if ( ! window.confirm( sfdsData.i18n.confirmDownload ) ) {
			return;
		}

		var scope = $( '#sfds-db-scope' ).val();

		// Disable button and show progress.
		$btnDbDl.prop( 'disabled', true )
			.find( '.dashicons' )
			.addClass( 'sfds-spinner' );
		$dbProgText.text( sfdsData.i18n.dbGenerating );
		$dbProgress.addClass( 'is-visible' );

		// Send AJAX request — server builds SQL and returns it as base64 JSON.
		doAjax( 'sfds_db_download', { scope: scope }, function ( data ) {
			// Re-enable button.
			$btnDbDl.prop( 'disabled', false )
				.find( '.dashicons' )
				.removeClass( 'sfds-spinner' );

			if ( ! data.sql || ! data.filename ) {
				$dbProgText.text( sfdsData.i18n.dbError );
				return;
			}

			// Decode base64 → binary string → Uint8Array for reliable Blob creation.
			var binary = window.atob( data.sql );
			var bytes  = new Uint8Array( binary.length );
			for ( var i = 0; i < binary.length; i++ ) {
				bytes[ i ] = binary.charCodeAt( i );
			}

			triggerDownload(
				bytes,
				data.filename,
				'application/octet-stream'
			);

			$dbProgText.text( sfdsData.i18n.dbDone );

			// Hide progress after 3 seconds.
			setTimeout( function () {
				$dbProgress.removeClass( 'is-visible' );
			}, 3000 );
		} );
	} );

} )( jQuery );