<?php
/**
 * 2FA enrollment UI shown on the user profile page.
 * Variables in scope: $user, $enabled, $secret, $uri, $backup_codes, $new_codes
 *
 * phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
 * -- This file is `include`d from DEFSEC_Two_Factor::render_user_profile_section(),
 * so every variable declared here is method-scoped, not truly global.
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }
?>
<h2><?php esc_html_e( 'Two-factor authentication (Defyn)', 'defyn-security-manager' ); ?></h2>

<?php wp_nonce_field( 'defsec_2fa_' . $user->ID ); ?>

<?php if ( $new_codes && is_array( $new_codes ) ) : ?>
	<div class="notice notice-warning inline" style="padding:12px;">
		<p><strong><?php esc_html_e( 'Save these backup codes now — they are shown only once.', 'defyn-security-manager' ); ?></strong></p>
		<pre style="background:#f6f7f7;padding:12px;border:1px solid #c3c4c7;border-radius:4px;font-size:14px;line-height:1.6;"><?php echo esc_html( implode( "\n", $new_codes ) ); ?></pre>
		<p><?php esc_html_e( 'Each code works once. Store them in a password manager.', 'defyn-security-manager' ); ?></p>
	</div>
<?php endif; ?>

<table class="form-table" role="presentation">
	<?php if ( ! $enabled ) :
		$qr_svg = DEFSEC_QR::svg( $uri, 5, 4 );  // 5px per module, 4-module quiet zone
		?>
		<tr>
			<th><?php esc_html_e( 'Set up authenticator', 'defyn-security-manager' ); ?></th>
			<td>
				<p>
					<?php esc_html_e( 'Scan this QR code with your authenticator app (Google Authenticator, Authy, 1Password, Bitwarden, Microsoft Authenticator, etc.), then enter a code below to confirm.', 'defyn-security-manager' ); ?>
				</p>
				<div style="display:flex;gap:24px;align-items:flex-start;flex-wrap:wrap;margin:14px 0;">
					<div style="background:#fff;padding:10px;border:1px solid #c3c4c7;border-radius:6px;line-height:0;">
						<?php if ( $qr_svg ) :
							// SVG is generated server-side by DEFSEC_QR::svg() from a Base32 secret +
							// pre-encoded otpauth URI — no user input reaches the output. Still
							// passed through wp_kses() with an explicit allowed-tag whitelist so
							// WP.org Plugin Check's static analyzer accepts the echo as escaped.
							echo wp_kses(
								$qr_svg,
								[
									'svg'  => [ 'xmlns' => true, 'width' => true, 'height' => true, 'viewbox' => true, 'shape-rendering' => true ],
									'rect' => [ 'x' => true, 'y' => true, 'width' => true, 'height' => true, 'fill' => true ],
									'g'    => [ 'fill' => true ],
								]
							);
						else : ?>
							<div style="width:230px;height:230px;display:flex;align-items:center;justify-content:center;color:#646970;font-size:12px;text-align:center;padding:10px;line-height:1.4;">
								<?php esc_html_e( 'QR rendering unavailable for this URI length. Use the manual entry option below.', 'defyn-security-manager' ); ?>
							</div>
						<?php endif; ?>
					</div>
					<div style="flex:1;min-width:260px;">
						<p style="margin-top:0;">
							<strong><?php esc_html_e( 'Can\'t scan?', 'defyn-security-manager' ); ?></strong>
							<?php esc_html_e( 'Enter this secret manually instead:', 'defyn-security-manager' ); ?>
						</p>
						<code style="user-select:all;display:inline-block;font-size:14px;padding:6px 10px;background:#f6f7f7;border:1px solid #c3c4c7;border-radius:4px;letter-spacing:0.05em;"><?php echo esc_html( chunk_split( $secret, 4, ' ' ) ); ?></code>
						<details style="margin-top:14px;">
							<summary style="cursor:pointer;color:#646970;font-size:12px;"><?php esc_html_e( 'Show otpauth:// URI', 'defyn-security-manager' ); ?></summary>
							<a href="<?php echo esc_url( $uri ); ?>" style="word-break:break-all;font-family:monospace;font-size:11px;display:block;margin-top:6px;color:#2271b1;">
								<?php echo esc_html( $uri ); ?>
							</a>
						</details>
					</div>
				</div>
				<p>
					<label for="defsec_enroll_code"><?php esc_html_e( 'Enter the 6-digit code from your app:', 'defyn-security-manager' ); ?></label><br />
					<input type="text" id="defsec_enroll_code" name="defsec_enroll_code"
					       inputmode="numeric" autocomplete="one-time-code"
					       style="font-size:1.2em;letter-spacing:0.2em;width:140px;text-align:center;" />
				</p>
				<p>
					<button type="submit" name="defsec_2fa_action" value="enable" class="button button-primary">
						<?php esc_html_e( 'Enable 2FA', 'defyn-security-manager' ); ?>
					</button>
				</p>
			</td>
		</tr>
	<?php else : ?>
		<tr>
			<th><?php esc_html_e( 'Status', 'defyn-security-manager' ); ?></th>
			<td>
				<strong style="color:#00a32a;"><?php esc_html_e( 'Enabled', 'defyn-security-manager' ); ?></strong>
				<p class="description">
					<?php
					printf(
						/* translators: %d: number of remaining backup codes */
						esc_html( _n( '%d backup code remaining.', '%d backup codes remaining.', count( (array) $backup_codes ), 'defyn-security-manager' ) ),
						count( (array) $backup_codes )
					);
					?>
				</p>
				<p>
					<button type="submit" name="defsec_2fa_action" value="regenerate_codes" class="button">
						<?php esc_html_e( 'Regenerate backup codes', 'defyn-security-manager' ); ?>
					</button>
					<button type="submit" name="defsec_2fa_action" value="disable" class="button button-link-delete"
					        onclick="return confirm('<?php esc_attr_e( 'Disable 2FA for this account?', 'defyn-security-manager' ); ?>');">
						<?php esc_html_e( 'Disable 2FA', 'defyn-security-manager' ); ?>
					</button>
				</p>
			</td>
		</tr>
	<?php endif; ?>
</table>
