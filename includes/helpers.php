<?php
/**
 * Shared utility helpers.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Return the client IP, honoring trusted proxy headers only when a constant opts in.
 *
 * Why: REMOTE_ADDR alone is wrong behind Cloudflare/load balancers, but blindly trusting
 * X-Forwarded-For lets any attacker spoof their IP. Site owners opt-in by defining
 * DEFSEC_TRUST_PROXY in wp-config.php once they've vetted their proxy chain.
 */
function defsec_client_ip(): string {
	if ( defined( 'DEFSEC_TRUST_PROXY' ) && DEFSEC_TRUST_PROXY ) {
		foreach ( [ 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR' ] as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				$candidate = explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) ) )[0];
				$candidate = trim( $candidate );
				if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
					return $candidate;
				}
			}
		}
	}

	$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	return filter_var( $remote, FILTER_VALIDATE_IP ) ? $remote : '0.0.0.0';
}

/**
 * Check whether the given IP is contained in a list of IPs or CIDR ranges.
 */
function defsec_ip_in_list( string $ip, array $list ): bool {
	if ( empty( $list ) ) {
		return false;
	}
	$packed_ip = @inet_pton( $ip );
	if ( $packed_ip === false ) {
		return false;
	}

	foreach ( $list as $entry ) {
		$entry = trim( $entry );
		if ( $entry === '' ) {
			continue;
		}
		if ( strpos( $entry, '/' ) === false ) {
			if ( $entry === $ip ) {
				return true;
			}
			continue;
		}
		[ $subnet, $bits ] = explode( '/', $entry, 2 );
		$packed_subnet     = @inet_pton( $subnet );
		if ( $packed_subnet === false ) {
			continue;
		}
		if ( strlen( $packed_subnet ) !== strlen( $packed_ip ) ) {
			continue;
		}
		$bits      = (int) $bits;
		$full_bytes = intdiv( $bits, 8 );
		$remainder = $bits % 8;

		if ( $full_bytes > 0 && substr( $packed_subnet, 0, $full_bytes ) !== substr( $packed_ip, 0, $full_bytes ) ) {
			continue;
		}
		if ( $remainder === 0 ) {
			return true;
		}
		$mask = chr( 0xff << ( 8 - $remainder ) & 0xff );
		if ( ( $packed_subnet[ $full_bytes ] & $mask ) === ( $packed_ip[ $full_bytes ] & $mask ) ) {
			return true;
		}
	}
	return false;
}

/**
 * Generate a cryptographically random alphanumeric string suitable for slugs/keys.
 */
function defsec_random_slug( int $length = 16 ): string {
	$bytes = random_bytes( max( 8, $length ) );
	return substr( strtolower( base_convert( bin2hex( $bytes ), 16, 36 ) ), 0, $length );
}

/**
 * Sanitize a slug used for the hidden login URL.
 *
 * Restricted to lowercase letters, numbers and hyphens; min 4 chars to avoid trivial guesses.
 */
function defsec_sanitize_slug( string $slug ): string {
	$slug = strtolower( trim( $slug ) );
	$slug = preg_replace( '/[^a-z0-9\-]/', '', $slug );
	$slug = trim( $slug, '-' );
	return $slug;
}

/**
 * Current site timezone object (respects WP timezone settings).
 */
function defsec_site_timezone(): DateTimeZone {
	$tz_string = get_option( 'timezone_string' );
	if ( $tz_string ) {
		try {
			return new DateTimeZone( $tz_string );
		} catch ( Exception $e ) {
			// fall through
		}
	}
	$offset  = (float) get_option( 'gmt_offset', 0 );
	$hours   = (int) $offset;
	$minutes = abs( ( $offset - $hours ) * 60 );
	$sign    = $offset >= 0 ? '+' : '-';
	$tz_name = sprintf( '%s%02d:%02d', $sign, abs( $hours ), $minutes );
	try {
		return new DateTimeZone( $tz_name );
	} catch ( Exception $e ) {
		return new DateTimeZone( 'UTC' );
	}
}
