<?php
/**
 * Minimal QR code encoder.
 *
 * Focused on a single purpose: render an SVG QR for a TOTP otpauth:// URI on the
 * 2FA enrolment screen. To keep the implementation tight and dependency-free, it
 * only supports the subset of the QR Code spec we actually need:
 *
 *   - Mode: byte mode only (otpauth URIs contain mixed case + special characters)
 *   - Error correction level: L (lowest, gives the most data capacity)
 *   - Versions: 1–9 (capacity ranges from 17 to 230 bytes — easily covers any
 *     otpauth URI; even a long site name + email leaves headroom)
 *   - Mask pattern: 0, i.e. (row + col) % 2 == 0. Scanners try all 8 masks when
 *     reading, so picking a fixed one is fine — visual scoring would only affect
 *     aesthetics, not scannability.
 *   - Output: inline SVG (works without GD/Imagick, scales cleanly).
 *
 * Algorithm reference: ISO/IEC 18004:2015. The block sizes, alignment-pattern
 * centers, and BCH/Reed-Solomon generators are taken directly from that spec.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class DSM_QR {

	/**
	 * QR version data for byte mode, error correction level L.
	 * Schema per row: [ alignment_centers, total_codewords, blocks_count, data_per_block, ec_per_block ]
	 *
	 * Block layout is symmetric within a version at level L (each block has the same
	 * size). For asymmetric layouts (V10+ at level L, others elsewhere) we'd need
	 * group bookkeeping; we cap at V9 here to keep the code straightforward.
	 */
	private const VERSIONS = [
		1 => [ [],          26,  1, 19,   7 ],
		2 => [ [ 6, 18 ],   44,  1, 34,  10 ],
		3 => [ [ 6, 22 ],   70,  1, 55,  15 ],
		4 => [ [ 6, 26 ],   100, 1, 80,  20 ],
		5 => [ [ 6, 30 ],   134, 1, 108, 26 ],
		6 => [ [ 6, 34 ],   172, 2, 68,  18 ],
		7 => [ [ 6, 22, 38 ], 196, 2, 78,  20 ],
		8 => [ [ 6, 24, 42 ], 242, 2, 97,  24 ],
		9 => [ [ 6, 26, 46 ], 292, 2, 116, 30 ],
	];

	private const PAD_BYTE_0 = 0xEC; // 11101100
	private const PAD_BYTE_1 = 0x11; // 00010001
	private const MASK       = 0;    // (row + col) % 2 == 0

	/**
	 * Encode `$text` and return an SVG string, or null if the text exceeds the
	 * supported capacity (230 bytes).
	 */
	public static function svg( string $text, int $module_px = 6, int $quiet = 4, string $fg = '#000', string $bg = '#fff' ): ?string {
		$bytes = array_values( unpack( 'C*', $text ) ?: [] );
		$len   = count( $bytes );

		// Pick the smallest version that can hold the data.
		$version = null;
		$config  = null;
		foreach ( self::VERSIONS as $v => $info ) {
			$data_capacity_bits = $info[2] * $info[3] * 8;
			$bits_needed        = 4 /* mode */ + ( $v <= 9 ? 8 : 16 ) /* length indicator */ + 8 * $len;
			if ( $bits_needed <= $data_capacity_bits ) {
				$version = $v;
				$config  = $info;
				break;
			}
		}
		if ( $version === null ) {
			return null;
		}

		[ $alignments, , $num_blocks, $data_per_block, $ec_per_block ] = $config;
		$data_codewords_total = $num_blocks * $data_per_block;

		// Build the bit stream: mode + length + data + terminator + zero pad + 0xEC/0x11 fill.
		$bits = '0100'; // byte mode
		$bits .= str_pad( decbin( $len ), 8, '0', STR_PAD_LEFT );
		foreach ( $bytes as $b ) {
			$bits .= str_pad( decbin( $b ), 8, '0', STR_PAD_LEFT );
		}
		$capacity_bits = $data_codewords_total * 8;
		$terminator    = min( 4, $capacity_bits - strlen( $bits ) );
		$bits         .= str_repeat( '0', $terminator );
		while ( strlen( $bits ) % 8 !== 0 ) {
			$bits .= '0';
		}

		$codewords = [];
		for ( $i = 0, $n = strlen( $bits ); $i < $n; $i += 8 ) {
			$codewords[] = bindec( substr( $bits, $i, 8 ) );
		}
		for ( $i = 0; count( $codewords ) < $data_codewords_total; $i++ ) {
			$codewords[] = ( $i % 2 === 0 ) ? self::PAD_BYTE_0 : self::PAD_BYTE_1;
		}

		// Reed-Solomon error correction per block.
		$blocks_data = [];
		$blocks_ec   = [];
		for ( $b = 0; $b < $num_blocks; $b++ ) {
			$slice         = array_slice( $codewords, $b * $data_per_block, $data_per_block );
			$blocks_data[] = $slice;
			$blocks_ec[]   = self::reed_solomon( $slice, $ec_per_block );
		}

		// Interleave: column-wise across all blocks.
		$final = [];
		for ( $i = 0; $i < $data_per_block; $i++ ) {
			foreach ( $blocks_data as $bd ) {
				$final[] = $bd[ $i ];
			}
		}
		for ( $i = 0; $i < $ec_per_block; $i++ ) {
			foreach ( $blocks_ec as $be ) {
				$final[] = $be[ $i ];
			}
		}

		$bitstream = '';
		foreach ( $final as $cw ) {
			$bitstream .= str_pad( decbin( $cw ), 8, '0', STR_PAD_LEFT );
		}

		// Build the matrix.
		$size   = 17 + 4 * $version;
		$matrix = self::build_matrix( $size, $version, $alignments, $bitstream );

		return self::render_svg( $matrix, $size, $module_px, $quiet, $fg, $bg );
	}

	/**
	 * Reed-Solomon error correction over GF(256), primitive polynomial 0x11D.
	 */
	private static function reed_solomon( array $data, int $ec_count ): array {
		[ $exp, $log ] = self::gf_tables();

		// Build the generator polynomial g(x) = (x + α^0)(x + α^1)...(x + α^(ec_count-1)).
		$gen = [ 1 ];
		for ( $i = 0; $i < $ec_count; $i++ ) {
			$next = array_fill( 0, count( $gen ) + 1, 0 );
			for ( $j = 0; $j < count( $gen ); $j++ ) {
				$next[ $j ] ^= $gen[ $j ];
				if ( $gen[ $j ] !== 0 ) {
					$next[ $j + 1 ] ^= $exp[ ( $log[ $gen[ $j ] ] + $i ) % 255 ];
				}
			}
			$gen = $next;
		}

		// Polynomial long division: (data << ec_count) / gen, remainder = EC codewords.
		$buf = array_merge( $data, array_fill( 0, $ec_count, 0 ) );
		$dn  = count( $data );
		$gn  = count( $gen );
		for ( $i = 0; $i < $dn; $i++ ) {
			$lead = $buf[ $i ];
			if ( $lead === 0 ) {
				continue;
			}
			$lead_log = $log[ $lead ];
			for ( $j = 0; $j < $gn; $j++ ) {
				if ( $gen[ $j ] !== 0 ) {
					$buf[ $i + $j ] ^= $exp[ ( $log[ $gen[ $j ] ] + $lead_log ) % 255 ];
				}
			}
		}
		return array_slice( $buf, $dn );
	}

	private static function gf_tables(): array {
		static $cache = null;
		if ( $cache ) {
			return $cache;
		}
		$exp = array_fill( 0, 256, 0 );
		$log = array_fill( 0, 256, 0 );
		$x   = 1;
		for ( $i = 0; $i < 255; $i++ ) {
			$exp[ $i ] = $x;
			$log[ $x ] = $i;
			$x <<= 1;
			if ( $x & 0x100 ) {
				$x ^= 0x11D;
			}
		}
		$exp[ 255 ] = $exp[ 0 ];
		$cache      = [ $exp, $log ];
		return $cache;
	}

	/**
	 * Assemble the full QR matrix: function patterns first, then format/version info,
	 * then weave the data bitstream through the remaining cells with the mask applied.
	 */
	private static function build_matrix( int $size, int $version, array $alignments, string $bitstream ): array {
		$matrix   = array_fill( 0, $size, array_fill( 0, $size, 0 ) );
		$reserved = array_fill( 0, $size, array_fill( 0, $size, false ) );

		// Finder patterns at three corners (with surrounding separator).
		$place_finder = static function ( int $r, int $c ) use ( &$matrix, &$reserved, $size ): void {
			for ( $i = -1; $i <= 7; $i++ ) {
				for ( $j = -1; $j <= 7; $j++ ) {
					$rr = $r + $i;
					$cc = $c + $j;
					if ( $rr < 0 || $rr >= $size || $cc < 0 || $cc >= $size ) {
						continue;
					}
					$in_finder = ( $i >= 0 && $i <= 6 && $j >= 0 && $j <= 6 );
					if ( $in_finder ) {
						$edge   = ( $i === 0 || $i === 6 || $j === 0 || $j === 6 );
						$center = ( $i >= 2 && $i <= 4 && $j >= 2 && $j <= 4 );
						$matrix[ $rr ][ $cc ] = ( $edge || $center ) ? 1 : 0;
					} else {
						$matrix[ $rr ][ $cc ] = 0; // separator
					}
					$reserved[ $rr ][ $cc ] = true;
				}
			}
		};
		$place_finder( 0, 0 );
		$place_finder( 0, $size - 7 );
		$place_finder( $size - 7, 0 );

		// Timing patterns.
		for ( $i = 8; $i < $size - 8; $i++ ) {
			$bit                  = ( $i % 2 === 0 ) ? 1 : 0;
			$matrix[6][ $i ]      = $bit;
			$matrix[ $i ][6]      = $bit;
			$reserved[6][ $i ]    = true;
			$reserved[ $i ][6]    = true;
		}

		// Alignment patterns. Skip the three centres that overlap with finder patterns.
		if ( ! empty( $alignments ) ) {
			$last         = $alignments[ count( $alignments ) - 1 ];
			$place_align  = static function ( int $r, int $c ) use ( &$matrix, &$reserved ): void {
				for ( $i = -2; $i <= 2; $i++ ) {
					for ( $j = -2; $j <= 2; $j++ ) {
						$on_edge   = ( abs( $i ) === 2 || abs( $j ) === 2 );
						$is_center = ( $i === 0 && $j === 0 );
						$matrix[ $r + $i ][ $c + $j ]   = ( $on_edge || $is_center ) ? 1 : 0;
						$reserved[ $r + $i ][ $c + $j ] = true;
					}
				}
			};
			foreach ( $alignments as $r ) {
				foreach ( $alignments as $c ) {
					if ( ( $r === 6 && $c === 6 ) || ( $r === 6 && $c === $last ) || ( $r === $last && $c === 6 ) ) {
						continue;
					}
					$place_align( $r, $c );
				}
			}
		}

		// Format info + version info + the always-dark module.
		self::draw_format_info( $matrix, $reserved, $size );
		if ( $version >= 7 ) {
			self::draw_version_info( $matrix, $reserved, $size, $version );
		}
		$matrix[ $size - 8 ][8] = 1;
		$reserved[ $size - 8 ][8] = true;

		// Data placement (zigzag from bottom-right) with mask applied.
		$bit_idx  = 0;
		$bit_len  = strlen( $bitstream );
		$col      = $size - 1;
		$going_up = true;
		while ( $col > 0 ) {
			if ( $col === 6 ) {
				// Skip the timing column.
				$col--;
				continue;
			}
			for ( $i = 0; $i < $size; $i++ ) {
				$row = $going_up ? ( $size - 1 - $i ) : $i;
				foreach ( [ $col, $col - 1 ] as $c ) {
					if ( $reserved[ $row ][ $c ] ) {
						continue;
					}
					$bit = ( $bit_idx < $bit_len ) ? (int) $bitstream[ $bit_idx ] : 0;
					$bit_idx++;
					if ( ( $row + $c ) % 2 === 0 ) {
						$bit ^= 1; // mask 0
					}
					$matrix[ $row ][ $c ] = $bit;
				}
			}
			$col      -= 2;
			$going_up  = ! $going_up;
		}

		return $matrix;
	}

	/**
	 * Write the 15-bit format information into both copies (top-left L + split bottom/right).
	 */
	private static function draw_format_info( array &$matrix, array &$reserved, int $size ): void {
		// 5 data bits: error level (L=01) << 3 | mask (0).
		$data = ( 0b01 << 3 ) | self::MASK;
		// BCH(15,5) with generator 0x537.
		$rem = $data;
		for ( $i = 0; $i < 10; $i++ ) {
			$rem = ( $rem << 1 ) ^ ( ( $rem >> 9 ) * 0x537 );
		}
		$bits = ( ( $data << 10 ) | ( $rem & 0x3FF ) ) ^ 0x5412;

		$set = static function ( int $r, int $c, int $v ) use ( &$matrix, &$reserved ): void {
			$matrix[ $r ][ $c ]   = $v;
			$reserved[ $r ][ $c ] = true;
		};

		// First copy (around top-left finder).
		for ( $i = 0; $i < 6; $i++ ) {
			$set( 8, $i, ( $bits >> $i ) & 1 );
		}
		$set( 8, 7, ( $bits >> 6 ) & 1 );
		$set( 8, 8, ( $bits >> 7 ) & 1 );
		$set( 7, 8, ( $bits >> 8 ) & 1 );
		for ( $i = 9; $i < 15; $i++ ) {
			$set( 14 - $i, 8, ( $bits >> $i ) & 1 );
		}

		// Second copy.
		for ( $i = 0; $i < 8; $i++ ) {
			$set( $size - 1 - $i, 8, ( $bits >> $i ) & 1 );
		}
		for ( $i = 8; $i < 15; $i++ ) {
			$set( 8, $size - 15 + $i, ( $bits >> $i ) & 1 );
		}
	}

	/**
	 * 18-bit version information, used for V7+.
	 */
	private static function draw_version_info( array &$matrix, array &$reserved, int $size, int $version ): void {
		// BCH(18, 6) with generator 0x1F25.
		$rem = $version;
		for ( $i = 0; $i < 12; $i++ ) {
			$rem = ( $rem << 1 ) ^ ( ( $rem >> 11 ) * 0x1F25 );
		}
		$bits = ( $version << 12 ) | ( $rem & 0xFFF );

		for ( $i = 0; $i < 18; $i++ ) {
			$bit = ( $bits >> $i ) & 1;
			$a   = $size - 11 + ( $i % 3 );
			$b   = intdiv( $i, 3 );
			$matrix[ $a ][ $b ] = $bit;
			$reserved[ $a ][ $b ] = true;
			$matrix[ $b ][ $a ] = $bit;
			$reserved[ $b ][ $a ] = true;
		}
	}

	private static function render_svg( array $matrix, int $size, int $module_px, int $quiet, string $fg, string $bg ): string {
		$total = ( $size + 2 * $quiet ) * $module_px;
		$out   = '<svg xmlns="http://www.w3.org/2000/svg" width="' . $total . '" height="' . $total . '" viewBox="0 0 ' . $total . ' ' . $total . '" shape-rendering="crispEdges">';
		$out  .= '<rect width="' . $total . '" height="' . $total . '" fill="' . htmlspecialchars( $bg, ENT_QUOTES ) . '"/>';
		$out  .= '<g fill="' . htmlspecialchars( $fg, ENT_QUOTES ) . '">';
		for ( $r = 0; $r < $size; $r++ ) {
			for ( $c = 0; $c < $size; $c++ ) {
				if ( $matrix[ $r ][ $c ] === 1 ) {
					$x    = ( $c + $quiet ) * $module_px;
					$y    = ( $r + $quiet ) * $module_px;
					$out .= '<rect x="' . $x . '" y="' . $y . '" width="' . $module_px . '" height="' . $module_px . '"/>';
				}
			}
		}
		$out .= '</g></svg>';
		return $out;
	}
}
