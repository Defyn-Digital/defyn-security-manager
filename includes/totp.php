<?php
/**
 * Self-contained RFC 6238 TOTP + Base32 helpers.
 *
 * Avoids pulling a Composer dependency for what is ~80 lines of well-defined RFC code.
 * Compatible with Google Authenticator, Authy, 1Password, etc.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class DEFSEC_TOTP {

	const PERIOD = 30;
	const DIGITS = 6;
	const ALGO   = 'sha1';

	/**
	 * Generate a fresh Base32-encoded secret (160 bits — Google Authenticator-compatible).
	 */
	public static function generate_secret(): string {
		return self::base32_encode( random_bytes( 20 ) );
	}

	/**
	 * Verify a user-supplied code against the secret, allowing a ±1 step drift.
	 */
	public static function verify( string $secret, string $code, int $window = 1 ): bool {
		$code = preg_replace( '/\s+/', '', $code );
		if ( ! preg_match( '/^\d{' . self::DIGITS . '}$/', $code ) ) {
			return false;
		}
		$timestep = (int) floor( time() / self::PERIOD );
		for ( $i = -$window; $i <= $window; $i++ ) {
			if ( hash_equals( self::at( $secret, $timestep + $i ), $code ) ) {
				return true;
			}
		}
		return false;
	}

	public static function at( string $secret, int $counter ): string {
		$key = self::base32_decode( $secret );
		if ( $key === '' ) {
			return '';
		}
		$bin_counter = pack( 'N*', 0, $counter );
		$hash        = hash_hmac( self::ALGO, $bin_counter, $key, true );
		$offset      = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0f;
		$truncated   = ( ( ord( $hash[ $offset ] ) & 0x7f ) << 24 )
		             | ( ( ord( $hash[ $offset + 1 ] ) & 0xff ) << 16 )
		             | ( ( ord( $hash[ $offset + 2 ] ) & 0xff ) << 8 )
		             | ( ord( $hash[ $offset + 3 ] ) & 0xff );
		return str_pad( (string) ( $truncated % ( 10 ** self::DIGITS ) ), self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Build the otpauth:// URI scanned by authenticator apps.
	 */
	public static function provisioning_uri( string $secret, string $account, string $issuer ): string {
		$label = rawurlencode( $issuer . ':' . $account );
		$params = http_build_query( [
			'secret'    => $secret,
			'issuer'    => $issuer,
			'algorithm' => strtoupper( self::ALGO ),
			'digits'    => self::DIGITS,
			'period'    => self::PERIOD,
		] );
		return "otpauth://totp/{$label}?{$params}";
	}

	public static function base32_encode( string $bytes ): string {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$binary   = '';
		for ( $i = 0; $i < strlen( $bytes ); $i++ ) {
			$binary .= str_pad( decbin( ord( $bytes[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $binary, 5 ) as $chunk ) {
			$chunk = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
			$out .= $alphabet[ bindec( $chunk ) ];
		}
		return $out;
	}

	public static function base32_decode( string $b32 ): string {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$b32 = strtoupper( preg_replace( '/[^A-Z2-7]/', '', $b32 ) );
		$binary = '';
		for ( $i = 0; $i < strlen( $b32 ); $i++ ) {
			$pos = strpos( $alphabet, $b32[ $i ] );
			if ( $pos === false ) {
				continue;
			}
			$binary .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $binary, 8 ) as $byte ) {
			if ( strlen( $byte ) === 8 ) {
				$out .= chr( bindec( $byte ) );
			}
		}
		return $out;
	}

	/**
	 * Generate human-friendly one-time backup codes.
	 */
	public static function generate_backup_codes( int $count = 8 ): array {
		$codes = [];
		for ( $i = 0; $i < $count; $i++ ) {
			$raw = bin2hex( random_bytes( 5 ) ); // 10 hex chars
			$codes[] = strtoupper( substr( $raw, 0, 5 ) . '-' . substr( $raw, 5, 5 ) );
		}
		return $codes;
	}
}
