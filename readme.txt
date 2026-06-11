=== ScanForge Database Security ===
Contributors: adnanlimdi
Tags: security, malware, database, scanner, cleanup
Requires at least: 5.0
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: scanforge-db-security

Scans and removes malicious scripts and malware injections from your WordPress database tables.

== Description ==

ScanForge Database Security helps WordPress administrators find and remove malicious code injected into the database. It scans common WordPress database tables for known malware patterns including traffic hijacking scripts, base64 encoded payloads, web shells, and other malicious injections.

= Features =

* Scans wp_posts, wp_options, wp_postmeta, wp_usermeta, and wp_comments tables
* Detects 15+ known malware patterns
* Clean individual rows or all threats at once
* Export scan results as CSV report
* Simple and easy to use admin interface
* No external service required — runs entirely on your server
* Follows WordPress coding standards

= Detected Threats =

* Traffic hijacking scripts (e.g. searchranktraffic.live)
* Nulled plugin backdoors (e.g. wordpressnull.org)
* Base64 encoded payloads
* Obfuscated eval() injections
* Dynamic script injections
* Tracking cookie injections
* Character code obfuscation
* Shell execution attempts (shell_exec, passthru)
* Web shells (FilesMan, c99shell, r57shell)

= Important Notice =

This plugin helps clean database infections but it does NOT prevent reinfection if the source of the malware (such as nulled/pirated plugins or themes) is still installed. Always remove nulled software and use legitimate licensed plugins to permanently fix infections.

= Usage =

1. Go to **ScanForge Database Security** in your WordPress admin menu
2. Click **Scan Database**
3. Review the threats found
4. Click **Clean All** or clean rows individually
5. Export a CSV report if needed
6. Run the scan again to verify everything is clean

== Installation ==

= Automatic Installation =

1. Go to **Plugins > Add New** in your WordPress admin
2. Search for "ScanForge Database Security"
3. Click **Install Now** and then **Activate**

= Manual Installation =

1. Download the plugin zip file
2. Go to **Plugins > Add New > Upload Plugin**
3. Upload the zip file and click **Install Now**
4. Click **Activate Plugin**

= After Installation =

Navigate to **ScanForge Database Security** in your WordPress admin sidebar to start scanning.

== Frequently Asked Questions ==

= Will this plugin prevent future infections? =

No. This plugin cleans existing infections. To prevent future infections you must remove all nulled/pirated plugins and themes, keep all software updated, and use a firewall plugin like Wordfence.

= Is it safe to use Clean All? =

Always take a full database backup before using Clean All. The plugin removes malicious script blocks while preserving your legitimate content, but a backup is always recommended.

= What tables does it scan? =

It scans: wp_posts, wp_options, wp_postmeta, wp_usermeta, and wp_comments.

= Can I export the scan results? =

Yes. After scanning, click the Export Report button to download a CSV file of all threats found.

= Does it work with custom table prefixes? =

Yes. The plugin uses WordPress's $wpdb object which automatically handles custom table prefixes.

== Screenshots ==

1. Main scanner interface showing scan results
2. Threat details with clean action buttons
3. Scan complete — database clean confirmation

== Changelog ==

= 1.0.0 =
* Initial release
* Scan wp_posts, wp_options, wp_postmeta, wp_usermeta, wp_comments
* Detect 15+ malware patterns
* Clean individual rows or all threats
* Export CSV report

== Upgrade Notice ==

= 1.0.0 =
Initial release.
