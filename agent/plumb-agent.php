<?php
/**
 * Plugin Name:       Plumb Agent
 * Description:       Read-only, signed endpoint that reports WordPress core, plugin, and theme versions to a Plumb collector. Nothing is reported to anyone without a valid signature.
 * Version:           1.0.0
 * Requires at least: 5.6
 * Requires PHP:      7.4
 * Author:            Plumb
 * License:           GPL-2.0-or-later
 * Network:           true
 *
 * Install as a must-use plugin (wp-content/mu-plugins/plumb-agent.php) so it
 * can't be deactivated from wp-admin. It also works as a regular plugin.
 *
 * Security model
 * --------------
 * - One GET route: /wp-json/plumb/v1/report. It takes no input that changes
 *   behavior and never writes anything except its own replay/rate-limit state.
 * - Every request must carry an HMAC-SHA256 signature over a timestamp and a
 *   one-time nonce, made with a secret unique to this site. Requests older than
 *   5 minutes, or reusing a nonce, are refused.
 * - Optional allowlist of puller IPs/CIDRs, checked before the signature.
 * - Anything that fails gets the same 404 that WordPress returns for a route
 *   that doesn't exist, and the route is hidden from the public /wp-json index.
 * - The response is signed too, bound to the request's nonce, so the collector
 *   can tell a genuine report from a cached or substituted one.
 * - The secret is read from the PLUMB_AGENT_SECRET constant (wp-config.php) or
 *   environment variable first; the database is a fallback only.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Plumb_Agent {

	const VERSION     = '1.0.0';
	const REST_NS     = 'plumb/v1';
	const REST_ROUTE  = '/report';
	const OPT         = 'plumb_agent_settings';
	const OPT_SECRET  = 'plumb_agent_secret';
	const OPT_LOG     = 'plumb_agent_log';
	const MAX_SKEW    = 300;   // seconds a signed request stays valid
	const NONCE_TTL   = 900;   // seconds a used nonce is remembered (> 2 x MAX_SKEW)
	const FAIL_LIMIT  = 10;    // rejected requests per IP ...
	const FAIL_WINDOW = 900;   // ... per 15 minutes before that IP is ignored
	const LOG_KEEP    = 25;
	const NOT_FOUND   = 'No route was found matching the URL and request method.';

	/** Where the client IP can come from, and what to tell the admin about each. */
	public static function ip_sources() {
		return array(
			'REMOTE_ADDR'           => 'REMOTE_ADDR (direct connection; safest default)',
			'HTTP_X_FORWARDED_FOR'  => 'X-Forwarded-For (last entry; only if your host or proxy sets it)',
			'HTTP_X_REAL_IP'        => 'X-Real-IP (only if your host or proxy sets it)',
			'HTTP_CF_CONNECTING_IP' => 'CF-Connecting-IP (only if the site is behind Cloudflare)',
			'HTTP_TRUE_CLIENT_IP'   => 'True-Client-IP (only if your CDN sets it)',
		);
	}

	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'register_route' ) );
		if ( is_multisite() ) {
			add_action( 'network_admin_menu', array( __CLASS__, 'admin_menu' ) );
			add_action( 'network_admin_edit_plumb_agent_save', array( __CLASS__, 'handle_save' ) );
			add_action( 'network_admin_edit_plumb_agent_secret', array( __CLASS__, 'handle_secret' ) );
		} else {
			add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ) );
			add_action( 'admin_post_plumb_agent_save', array( __CLASS__, 'handle_save' ) );
			add_action( 'admin_post_plumb_agent_secret', array( __CLASS__, 'handle_secret' ) );
		}
	}

	// ------------------------------------------------------------------ storage

	private static function get_opt( $key, $default = false ) {
		return is_multisite() ? get_site_option( $key, $default ) : get_option( $key, $default );
	}

	private static function set_opt( $key, $value ) {
		return is_multisite() ? update_site_option( $key, $value ) : update_option( $key, $value, false );
	}

	public static function settings() {
		$defaults = array(
			'allowed_ips'   => array(),
			'ip_source'     => 'REMOTE_ADDR',
			'require_https' => true,
		);
		$s = self::get_opt( self::OPT, array() );
		return wp_parse_args( is_array( $s ) ? $s : array(), $defaults );
	}

	/** @return array{0: ?string, 1: string} secret and where it came from */
	public static function secret() {
		if ( defined( 'PLUMB_AGENT_SECRET' ) && is_string( PLUMB_AGENT_SECRET ) && strlen( PLUMB_AGENT_SECRET ) >= 32 ) {
			return array( PLUMB_AGENT_SECRET, 'constant' );
		}
		$env = getenv( 'PLUMB_AGENT_SECRET' );
		if ( is_string( $env ) && strlen( $env ) >= 32 ) {
			return array( $env, 'environment' );
		}
		$db = self::get_opt( self::OPT_SECRET, '' );
		if ( is_string( $db ) && strlen( $db ) >= 32 ) {
			return array( $db, 'database' );
		}
		return array( null, 'none' );
	}

	private static function log_event( $type, $ip, $reason = '' ) {
		$log = self::get_opt( self::OPT_LOG, array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}
		if ( 'success' === $type ) {
			$log['last_success'] = array( 'time' => time(), 'ip' => $ip );
		} else {
			$rejected   = isset( $log['rejected'] ) && is_array( $log['rejected'] ) ? $log['rejected'] : array();
			array_unshift( $rejected, array( 'time' => time(), 'ip' => $ip, 'reason' => $reason ) );
			$log['rejected'] = array_slice( $rejected, 0, self::LOG_KEEP );
		}
		self::set_opt( self::OPT_LOG, $log );
	}

	// ------------------------------------------------------------------ IP handling

	public static function client_ip( $source ) {
		$ip = '';
		switch ( $source ) {
			case 'HTTP_X_FORWARDED_FOR':
				// The last entry is the one added by the proxy nearest this server;
				// earlier entries are whatever the client claimed.
				$raw   = isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? (string) $_SERVER['HTTP_X_FORWARDED_FOR'] : '';
				$parts = array_values( array_filter( array_map( 'trim', explode( ',', $raw ) ) ) );
				$ip    = $parts ? $parts[ count( $parts ) - 1 ] : '';
				break;
			case 'HTTP_X_REAL_IP':
			case 'HTTP_CF_CONNECTING_IP':
			case 'HTTP_TRUE_CLIENT_IP':
				$ip = isset( $_SERVER[ $source ] ) ? trim( (string) $_SERVER[ $source ] ) : '';
				break;
			default:
				$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
		}
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
	}

	/** inet_pton, with IPv4-mapped IPv6 (::ffff:a.b.c.d) folded back to IPv4. */
	private static function pton( $ip ) {
		$b = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $b ) {
			return false;
		}
		if ( 16 === strlen( $b ) && substr( $b, 0, 12 ) === str_repeat( "\0", 10 ) . "\xff\xff" ) {
			return substr( $b, 12 );
		}
		return $b;
	}

	public static function valid_rule( $rule ) {
		$parts = explode( '/', $rule, 2 );
		$b     = self::pton( $parts[0] );
		if ( false === $b ) {
			return false;
		}
		if ( isset( $parts[1] ) ) {
			if ( ! ctype_digit( $parts[1] ) ) {
				return false;
			}
			$bits = (int) $parts[1];
			return $bits >= 0 && $bits <= strlen( $b ) * 8;
		}
		return true;
	}

	public static function ip_matches( $ip, $rule ) {
		$parts = explode( '/', $rule, 2 );
		$ipb   = self::pton( $ip );
		$netb  = self::pton( $parts[0] );
		if ( false === $ipb || false === $netb || strlen( $ipb ) !== strlen( $netb ) ) {
			return false;
		}
		$max  = strlen( $ipb ) * 8;
		$bits = isset( $parts[1] ) && ctype_digit( $parts[1] ) ? (int) $parts[1] : $max;
		if ( $bits < 0 || $bits > $max ) {
			return false;
		}
		$whole = intdiv( $bits, 8 );
		$rem   = $bits % 8;
		if ( substr( $ipb, 0, $whole ) !== substr( $netb, 0, $whole ) ) {
			return false;
		}
		if ( 0 === $rem ) {
			return true;
		}
		$mask = chr( ( 0xFF << ( 8 - $rem ) ) & 0xFF );
		return ( $ipb[ $whole ] & $mask ) === ( $netb[ $whole ] & $mask );
	}

	// ------------------------------------------------------------------ REST

	public static function register_route() {
		register_rest_route(
			self::REST_NS,
			self::REST_ROUTE,
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'report' ),
				'permission_callback' => array( __CLASS__, 'authorize' ),
				'show_in_index'       => false,
				'args'                => array(),
			)
		);
	}

	private static function fail_key( $ip ) {
		return 'plumb_f_' . substr( hash( 'sha256', $ip ), 0, 32 );
	}

	private static function deny( $ip, $reason ) {
		$key   = self::fail_key( $ip );
		$count = (int) get_site_transient( $key ) + 1;
		if ( $count >= self::FAIL_LIMIT ) {
			$reason .= '; address now ignored for 15 minutes';
		}
		self::log_event( 'rejected', $ip, $reason );
		set_site_transient( $key, $count, self::FAIL_WINDOW );
		// Same answer WordPress gives for a route that doesn't exist.
		return new WP_Error( 'rest_no_route', self::NOT_FOUND, array( 'status' => 404 ) );
	}

	public static function authorize( WP_REST_Request $req ) {
		// WordPress calls permission_callback again for the same request when it builds the
		// Allow header. Decide once per request; a second pass would see its own nonce as a
		// replay and count a false failure against the caller.
		static $decided = array();
		$id = spl_object_id( $req );
		if ( ! array_key_exists( $id, $decided ) ) {
			$decided[ $id ] = self::decide( $req );
		}
		return $decided[ $id ];
	}

	private static function decide( WP_REST_Request $req ) {
		$s  = self::settings();
		$ip = self::client_ip( $s['ip_source'] );

		// Checked first, and answered without logging: once an address is over the limit,
		// further requests from it cost a read, never a database write.
		if ( (int) get_site_transient( self::fail_key( $ip ) ) >= self::FAIL_LIMIT ) {
			return new WP_Error( 'rest_no_route', self::NOT_FOUND, array( 'status' => 404 ) );
		}
		if ( ! empty( $s['require_https'] ) && ! is_ssl() ) {
			return self::deny( $ip, 'not HTTPS' );
		}
		if ( ! empty( $s['allowed_ips'] ) ) {
			$allowed = false;
			foreach ( $s['allowed_ips'] as $rule ) {
				if ( '' !== $ip && self::ip_matches( $ip, $rule ) ) {
					$allowed = true;
					break;
				}
			}
			if ( ! $allowed ) {
				return self::deny( $ip, 'IP not on allowlist' );
			}
		}
		list( $secret ) = self::secret();
		if ( ! $secret ) {
			return self::deny( $ip, 'no secret configured' );
		}

		$ts    = (string) $req->get_header( 'x_plumb_timestamp' );
		$nonce = strtolower( (string) $req->get_header( 'x_plumb_nonce' ) );
		$sig   = strtolower( (string) $req->get_header( 'x_plumb_signature' ) );
		if ( ! ctype_digit( $ts ) || ! preg_match( '/^[a-f0-9]{32,128}$/', $nonce ) || ! preg_match( '/^[a-f0-9]{64}$/', $sig ) ) {
			return self::deny( $ip, 'missing or malformed signature headers' );
		}
		if ( abs( time() - (int) $ts ) > self::MAX_SKEW ) {
			return self::deny( $ip, 'timestamp outside 5-minute window (check clocks)' );
		}
		$expected = hash_hmac( 'sha256', "PLUMB1\nGET\n" . $req->get_route() . "\n{$ts}\n{$nonce}", $secret );
		if ( ! hash_equals( $expected, $sig ) ) {
			return self::deny( $ip, 'bad signature' );
		}
		$nkey = 'plumb_n_' . substr( hash( 'sha256', $nonce ), 0, 32 );
		if ( get_site_transient( $nkey ) ) {
			return self::deny( $ip, 'replayed nonce' );
		}
		set_site_transient( $nkey, 1, self::NONCE_TTL );

		self::log_event( 'success', $ip );
		return true;
	}

	public static function report( WP_REST_Request $req ) {
		list( $secret ) = self::secret();
		$nonce          = strtolower( (string) $req->get_header( 'x_plumb_nonce' ) );
		$body           = wp_json_encode( self::build_report(), JSON_UNESCAPED_SLASHES );
		$sig            = hash_hmac( 'sha256', "PLUMB1-RESP\n{$nonce}\n{$body}", $secret );

		nocache_headers();
		$res = new WP_REST_Response(
			array(
				'v'      => 1,
				'nonce'  => $nonce,
				'report' => $body,
				'sig'    => $sig,
			),
			200
		);
		$res->header( 'Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0, private' );
		return $res;
	}

	// ------------------------------------------------------------------ the report

	public static function build_report() {
		global $wpdb;
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		// Plugins
		$plugin_updates = get_site_transient( 'update_plugins' );
		$active         = (array) get_option( 'active_plugins', array() );
		$network_active = is_multisite() ? array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) : array();
		$auto_plugins   = (array) get_site_option( 'auto_update_plugins', array() );
		$plugins        = array();
		foreach ( get_plugins() as $file => $data ) {
			$u    = isset( $plugin_updates->response[ $file ] ) ? (object) $plugin_updates->response[ $file ] : null;
			$slug = '.' === dirname( $file ) ? basename( $file, '.php' ) : dirname( $file );
			if ( $u && ! empty( $u->slug ) ) {
				$slug = $u->slug;
			}
			if ( in_array( $file, $network_active, true ) ) {
				$status = 'network-active';
			} elseif ( in_array( $file, $active, true ) ) {
				$status = 'active';
			} else {
				$status = 'inactive';
			}
			$plugins[] = array(
				'file'           => $file,
				'slug'           => $slug,
				'name'           => $data['Name'],
				'version'        => $data['Version'],
				'status'         => $status,
				'update_version' => $u && isset( $u->new_version ) ? (string) $u->new_version : null,
				'auto_update'    => in_array( $file, $auto_plugins, true ),
			);
		}

		// Themes
		$theme_updates = get_site_transient( 'update_themes' );
		$auto_themes   = (array) get_site_option( 'auto_update_themes', array() );
		$stylesheet    = get_stylesheet();
		$template      = get_template();
		$themes        = array();
		foreach ( wp_get_themes() as $slug => $theme ) {
			$u = isset( $theme_updates->response[ $slug ] ) ? (array) $theme_updates->response[ $slug ] : null;
			if ( $slug === $stylesheet ) {
				$status = 'active';
			} elseif ( $slug === $template ) {
				$status = 'parent';
			} else {
				$status = 'inactive';
			}
			$themes[] = array(
				'slug'           => (string) $slug,
				'name'           => $theme->get( 'Name' ),
				'version'        => $theme->get( 'Version' ),
				'status'         => $status,
				'update_version' => $u && isset( $u['new_version'] ) ? (string) $u['new_version'] : null,
				'auto_update'    => in_array( $slug, $auto_themes, true ),
			);
		}

		// Must-use plugins and drop-ins: reported for visibility, not version-checked.
		$mu = array();
		foreach ( get_mu_plugins() as $file => $data ) {
			$mu[] = array( 'file' => $file, 'name' => $data['Name'], 'version' => $data['Version'] );
		}
		$dropins = array_keys( get_dropins() );

		// Core
		$core_update  = null;
		$core_updates = get_site_transient( 'update_core' );
		if ( $core_updates && ! empty( $core_updates->updates ) ) {
			foreach ( $core_updates->updates as $offer ) {
				if ( isset( $offer->response ) && 'upgrade' === $offer->response && isset( $offer->current ) ) {
					$core_update = (string) $offer->current;
					break;
				}
			}
		}

		return array(
			'agent_version' => self::VERSION,
			'generated_at'  => gmdate( 'c' ),
			'home_url'      => home_url(),
			'site_url'      => site_url(),
			'core'          => array(
				'version'        => get_bloginfo( 'version' ),
				'update_version' => $core_update,
			),
			'environment'   => array(
				'php_version' => PHP_VERSION,
				'db_server'   => method_exists( $wpdb, 'db_server_info' ) ? (string) $wpdb->db_server_info() : null,
				'multisite'   => is_multisite(),
				'site_count'  => is_multisite() ? (int) get_blog_count() : 1,
			),
			'flags'         => array(
				'file_editing_disabled' => defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT,
				'wp_debug'              => defined( 'WP_DEBUG' ) && WP_DEBUG,
				'wp_debug_display'      => defined( 'WP_DEBUG' ) && WP_DEBUG && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY ),
			),
			'update_checks' => array(
				'core'    => isset( $core_updates->last_checked ) ? (int) $core_updates->last_checked : null,
				'plugins' => isset( $plugin_updates->last_checked ) ? (int) $plugin_updates->last_checked : null,
				'themes'  => isset( $theme_updates->last_checked ) ? (int) $theme_updates->last_checked : null,
			),
			'plugins'       => $plugins,
			'themes'        => $themes,
			'mu_plugins'    => $mu,
			'dropins'       => $dropins,
		);
	}

	// ------------------------------------------------------------------ admin UI

	private static function cap() {
		return is_multisite() ? 'manage_network_options' : 'manage_options';
	}

	private static function page_url( $args = array() ) {
		$base = is_multisite() ? network_admin_url( 'settings.php?page=plumb-agent' ) : admin_url( 'options-general.php?page=plumb-agent' );
		return add_query_arg( $args, $base );
	}

	private static function form_action( $action ) {
		return is_multisite() ? network_admin_url( 'edit.php?action=' . $action ) : admin_url( 'admin-post.php' );
	}

	public static function admin_menu() {
		if ( is_multisite() ) {
			add_submenu_page( 'settings.php', 'Plumb Agent', 'Plumb Agent', self::cap(), 'plumb-agent', array( __CLASS__, 'render_page' ) );
		} else {
			add_options_page( 'Plumb Agent', 'Plumb Agent', self::cap(), 'plumb-agent', array( __CLASS__, 'render_page' ) );
		}
	}

	public static function handle_save() {
		if ( ! current_user_can( self::cap() ) ) {
			wp_die( 'Not allowed.', 403 );
		}
		check_admin_referer( 'plumb_agent_save' );

		$raw     = isset( $_POST['allowed_ips'] ) ? wp_unslash( (string) $_POST['allowed_ips'] ) : '';
		$rules   = array();
		$invalid = array();
		foreach ( preg_split( '/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY ) as $rule ) {
			$rule = trim( $rule );
			if ( self::valid_rule( $rule ) ) {
				$rules[] = $rule;
			} else {
				$invalid[] = $rule;
			}
		}
		$source = isset( $_POST['ip_source'] ) ? sanitize_text_field( wp_unslash( $_POST['ip_source'] ) ) : 'REMOTE_ADDR';
		if ( ! array_key_exists( $source, self::ip_sources() ) ) {
			$source = 'REMOTE_ADDR';
		}
		if ( $invalid ) {
			// Don't half-save an allowlist: an entry the admin thinks is there but isn't is worse than an error.
			set_site_transient( 'plumb_agent_invalid_' . get_current_user_id(), $invalid, 300 );
			wp_safe_redirect( self::page_url( array( 'plumb_msg' => 'invalid' ) ) );
			exit;
		}
		self::set_opt(
			self::OPT,
			array(
				'allowed_ips'   => array_values( array_unique( $rules ) ),
				'ip_source'     => $source,
				'require_https' => ! empty( $_POST['require_https'] ),
			)
		);
		wp_safe_redirect( self::page_url( array( 'plumb_msg' => 'saved' ) ) );
		exit;
	}

	public static function handle_secret() {
		if ( ! current_user_can( self::cap() ) ) {
			wp_die( 'Not allowed.', 403 );
		}
		check_admin_referer( 'plumb_agent_secret' );
		list( , $source ) = self::secret();
		if ( in_array( $source, array( 'constant', 'environment' ), true ) ) {
			wp_safe_redirect( self::page_url( array( 'plumb_msg' => 'managed' ) ) );
			exit;
		}
		$secret = bin2hex( random_bytes( 32 ) );
		self::set_opt( self::OPT_SECRET, $secret );
		// Show it once, to the admin who generated it, then it's gone from the UI.
		set_site_transient( 'plumb_agent_show_' . get_current_user_id(), $secret, 300 );
		wp_safe_redirect( self::page_url( array( 'plumb_msg' => 'secret' ) ) );
		exit;
	}

	public static function render_page() {
		if ( ! current_user_can( self::cap() ) ) {
			return;
		}
		$s                  = self::settings();
		list( , $source )   = self::secret();
		$log                = self::get_opt( self::OPT_LOG, array() );
		$msg                = isset( $_GET['plumb_msg'] ) ? sanitize_key( $_GET['plumb_msg'] ) : '';
		$uid                = get_current_user_id();
		$show_secret        = get_site_transient( 'plumb_agent_show_' . $uid );
		$invalid            = get_site_transient( 'plumb_agent_invalid_' . $uid );
		delete_site_transient( 'plumb_agent_show_' . $uid );
		delete_site_transient( 'plumb_agent_invalid_' . $uid );
		$endpoint           = rest_url( self::REST_NS . self::REST_ROUTE );
		$fmt                = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
		?>
		<div class="wrap">
			<h1>Plumb Agent <span style="font-size:13px;color:#646970;font-weight:400">v<?php echo esc_html( self::VERSION ); ?></span></h1>
			<p>Reports this site's WordPress core, plugin, and theme versions to your Plumb collector. Read-only: nothing on this site can be changed through it, and nothing is returned without a valid signature.</p>

			<?php if ( 'saved' === $msg ) : ?>
				<div class="notice notice-success"><p>Settings saved.</p></div>
			<?php elseif ( 'invalid' === $msg && is_array( $invalid ) ) : ?>
				<div class="notice notice-error"><p>Nothing was saved. These entries aren't valid IP addresses or CIDR ranges: <code><?php echo esc_html( implode( ', ', $invalid ) ); ?></code></p></div>
			<?php elseif ( 'managed' === $msg ) : ?>
				<div class="notice notice-warning"><p>The secret is set outside the database (wp-config.php or an environment variable). Change it there.</p></div>
			<?php endif; ?>

			<?php if ( $show_secret ) : ?>
				<div class="notice notice-warning" style="padding:12px">
					<p><strong>New secret. Copy it now; it won't be shown again.</strong></p>
					<p><code style="font-size:13px;user-select:all"><?php echo esc_html( $show_secret ); ?></code></p>
					<p>Better: move it out of the database. Add this line to <code>wp-config.php</code> above "That's all, stop editing":</p>
					<p><code style="user-select:all">define( 'PLUMB_AGENT_SECRET', '<?php echo esc_html( $show_secret ); ?>' );</code></p>
					<p>Put the same value in Plumb's <code>config/plumb.env</code> file, on the line for this site (<code>PLUMB_SECRET_</code> followed by the site's name in capitals), then run <code>docker compose up -d</code> on the Plumb computer.</p>
				</div>
			<?php endif; ?>

			<h2>Status</h2>
			<table class="widefat striped" style="max-width:900px">
				<tbody>
				<tr><td style="width:220px">Endpoint</td><td><code><?php echo esc_html( $endpoint ); ?></code></td></tr>
				<tr><td>Shared secret</td><td>
					<?php
					switch ( $source ) {
						case 'constant':
							echo '<strong>Set in wp-config.php</strong> (PLUMB_AGENT_SECRET). Recommended.';
							break;
						case 'environment':
							echo '<strong>Set as an environment variable</strong> (PLUMB_AGENT_SECRET).';
							break;
						case 'database':
							echo '<strong>Stored in the database.</strong> It works, but anything that can read this site\'s database can read it. Moving it to wp-config.php is safer.';
							break;
						default:
							echo '<strong style="color:#b32d2e">Not set.</strong> The endpoint refuses every request until a secret exists.';
					}
					?>
				</td></tr>
				<tr><td>Puller allowlist</td><td>
					<?php
					if ( empty( $s['allowed_ips'] ) ) {
						echo '<strong style="color:#b32d2e">Empty.</strong> Any address with a valid signature can pull. Add your Plumb server\'s address below.';
					} else {
						echo esc_html( implode( ', ', $s['allowed_ips'] ) );
					}
					?>
				</td></tr>
				<tr><td>This page loaded over HTTPS</td><td><?php echo is_ssl() ? 'Yes' : '<strong style="color:#b32d2e">No</strong>. If "Require HTTPS" is on and this site really is HTTPS, your host may not be passing the HTTPS flag to WordPress.'; ?></td></tr>
				</tbody>
			</table>

			<h2>Puller access</h2>
			<form method="post" action="<?php echo esc_url( self::form_action( 'plumb_agent_save' ) ); ?>">
				<input type="hidden" name="action" value="plumb_agent_save">
				<?php wp_nonce_field( 'plumb_agent_save' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="allowed_ips">Allowed puller IP addresses</label></th>
						<td>
							<textarea name="allowed_ips" id="allowed_ips" rows="4" cols="50" class="large-text code" placeholder="203.0.113.10&#10;2001:db8::/64"><?php echo esc_textarea( implode( "\n", $s['allowed_ips'] ) ); ?></textarea>
							<p class="description">One per line. IPv4, IPv6, or CIDR ranges. Requests from anywhere else are refused before the signature is even checked. Leave empty to rely on the signature alone (not recommended).</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="ip_source">Read the client IP from</label></th>
						<td>
							<select name="ip_source" id="ip_source">
								<?php foreach ( self::ip_sources() as $key => $label ) : ?>
									<option value="<?php echo esc_attr( $key ); ?>" <?php selected( $s['ip_source'], $key ); ?>><?php echo esc_html( $label ); ?></option>
								<?php endforeach; ?>
							</select>
							<p class="description">Behind a proxy or CDN, REMOTE_ADDR is the proxy, not the puller. Pick a header only if your host sets it; a header the client can set itself can be faked. The table below shows what this site sees for <em>your</em> current request, which helps you pick.</p>
							<table class="widefat" style="max-width:600px;margin-top:8px">
								<thead><tr><th>Source</th><th>Value for your request</th></tr></thead>
								<tbody>
								<?php foreach ( array_keys( self::ip_sources() ) as $key ) : ?>
									<tr><td><code><?php echo esc_html( $key ); ?></code></td><td><code><?php echo esc_html( self::client_ip( $key ) ?: '—' ); ?></code></td></tr>
								<?php endforeach; ?>
								</tbody>
							</table>
						</td>
					</tr>
					<tr>
						<th scope="row">Require HTTPS</th>
						<td><label><input type="checkbox" name="require_https" value="1" <?php checked( ! empty( $s['require_https'] ) ); ?>> Refuse requests that didn't arrive over HTTPS</label></td>
					</tr>
				</table>
				<?php submit_button( 'Save settings' ); ?>
			</form>

			<?php if ( ! in_array( $source, array( 'constant', 'environment' ), true ) ) : ?>
				<h2>Shared secret</h2>
				<form method="post" action="<?php echo esc_url( self::form_action( 'plumb_agent_secret' ) ); ?>" onsubmit="return <?php echo 'none' === $source ? 'true' : "confirm('Rotating the secret breaks Plumb\\'s access until you update config/plumb.env on the Plumb computer. Continue?')"; ?>;">
					<input type="hidden" name="action" value="plumb_agent_secret">
					<?php wp_nonce_field( 'plumb_agent_secret' ); ?>
					<p>Generates a new 256-bit secret, shows it once, and stores it in the database. Alternatively, generate one with <code>python3 collector.py --new-secret SITE_NAME</code> and put it in wp-config.php, which takes priority.</p>
					<?php submit_button( 'none' === $source ? 'Generate secret' : 'Rotate secret', 'secondary' ); ?>
				</form>
			<?php endif; ?>

			<h2>Recent activity</h2>
			<p>
				Last successful pull:
				<?php
				if ( ! empty( $log['last_success'] ) ) {
					echo '<strong>' . esc_html( wp_date( $fmt, (int) $log['last_success']['time'] ) ) . '</strong> from <code>' . esc_html( $log['last_success']['ip'] ?: 'unknown' ) . '</code>';
				} else {
					echo '<strong>never</strong>';
				}
				?>
			</p>
			<?php if ( ! empty( $log['rejected'] ) ) : ?>
				<table class="widefat striped" style="max-width:900px">
					<thead><tr><th>Rejected request</th><th>From</th><th>Reason</th></tr></thead>
					<tbody>
					<?php foreach ( $log['rejected'] as $r ) : ?>
						<tr>
							<td><?php echo esc_html( wp_date( $fmt, (int) $r['time'] ) ); ?></td>
							<td><code><?php echo esc_html( $r['ip'] ?: 'unknown' ); ?></code></td>
							<td><?php echo esc_html( $r['reason'] ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				<p class="description">Callers only ever see a 404. The real reason is recorded here, and only here.</p>
			<?php else : ?>
				<p>No rejected requests recorded.</p>
			<?php endif; ?>
		</div>
		<?php
	}
}

Plumb_Agent::init();
