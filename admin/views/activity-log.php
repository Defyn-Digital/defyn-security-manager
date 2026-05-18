<?php
/**
 * Activity log table. Variables in scope: $rows, $total, $filters, $page, $per_page.
 *
 * phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
 * -- This file is `include`d from DEFSEC_Admin::render_log_page(), so every
 * variable declared here is method-scoped, not truly global.
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }

$event_labels = [
	DEFSEC_Activity_Log::EVT_LOGIN_SUCCESS    => __( 'Login success', 'defyn-security-manager' ),
	DEFSEC_Activity_Log::EVT_LOGIN_FAILED     => __( 'Login failed', 'defyn-security-manager' ),
	DEFSEC_Activity_Log::EVT_LOCKOUT          => __( 'IP locked out', 'defyn-security-manager' ),
	DEFSEC_Activity_Log::EVT_HIDDEN_URL_SCAN  => __( 'Hidden URL scan', 'defyn-security-manager' ),
	DEFSEC_Activity_Log::EVT_TIME_WINDOW_DENY => __( 'Outside time window', 'defyn-security-manager' ),
	DEFSEC_Activity_Log::EVT_2FA_FAILED       => __( '2FA failed', 'defyn-security-manager' ),
	DEFSEC_Activity_Log::EVT_2FA_SUCCESS      => __( '2FA success', 'defyn-security-manager' ),
	DEFSEC_Activity_Log::EVT_2FA_ENROLLED     => __( '2FA enrolled', 'defyn-security-manager' ),
	DEFSEC_Activity_Log::EVT_2FA_DISABLED     => __( '2FA disabled', 'defyn-security-manager' ),
	DEFSEC_Activity_Log::EVT_SETTINGS_CHANGED => __( 'Settings changed', 'defyn-security-manager' ),
];

$total_pages = max( 1, (int) ceil( $total / $per_page ) );
$base_url    = admin_url( 'admin.php?page=' . DEFSEC_SLUG . '-log' );
?>
<div class="wrap defyn-bem-wrap">
	<h1><?php esc_html_e( 'Activity Log', 'defyn-security-manager' ); ?></h1>

	<form method="get" style="margin:18px 0;">
		<input type="hidden" name="page" value="<?php echo esc_attr( DEFSEC_SLUG . '-log' ); ?>" />
		<select name="event">
			<option value=""><?php esc_html_e( 'All events', 'defyn-security-manager' ); ?></option>
			<?php foreach ( $event_labels as $k => $label ) : ?>
				<option value="<?php echo esc_attr( $k ); ?>" <?php selected( $filters['event_type'], $k ); ?>>
					<?php echo esc_html( $label ); ?>
				</option>
			<?php endforeach; ?>
		</select>
		<input type="text" name="ip" placeholder="<?php esc_attr_e( 'IP address', 'defyn-security-manager' ); ?>"
		       value="<?php echo esc_attr( $filters['ip'] ); ?>" />
		<?php submit_button( __( 'Filter', 'defyn-security-manager' ), '', '', false ); ?>
	</form>

	<table class="wp-list-table widefat fixed striped">
		<thead>
			<tr>
				<th style="width:160px;"><?php esc_html_e( 'When (UTC)', 'defyn-security-manager' ); ?></th>
				<th style="width:160px;"><?php esc_html_e( 'Event', 'defyn-security-manager' ); ?></th>
				<th style="width:140px;"><?php esc_html_e( 'IP', 'defyn-security-manager' ); ?></th>
				<th><?php esc_html_e( 'Username', 'defyn-security-manager' ); ?></th>
				<th><?php esc_html_e( 'Details', 'defyn-security-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php if ( empty( $rows ) ) : ?>
			<tr><td colspan="5"><?php esc_html_e( 'No events recorded.', 'defyn-security-manager' ); ?></td></tr>
		<?php else : foreach ( $rows as $row ) :
			$details = $row['details'] ? json_decode( $row['details'], true ) : null; ?>
			<tr>
				<td><?php echo esc_html( $row['created_at'] ); ?></td>
				<td><?php echo esc_html( $event_labels[ $row['event_type'] ] ?? $row['event_type'] ); ?></td>
				<td><code><?php echo esc_html( $row['ip'] ); ?></code></td>
				<td><?php echo esc_html( $row['username'] ); ?></td>
				<td><code style="font-size:11px;"><?php echo $details ? esc_html( wp_json_encode( $details ) ) : ''; ?></code></td>
			</tr>
		<?php endforeach; endif; ?>
		</tbody>
	</table>

	<?php if ( $total_pages > 1 ) : ?>
		<div class="tablenav"><div class="tablenav-pages">
			<span class="displaying-num">
				<?php
				/* translators: %d: number of items */
				printf( esc_html( _n( '%d item', '%d items', $total, 'defyn-security-manager' ) ), (int) $total );
				?>
			</span>
			<?php
			$pagination = paginate_links( [
				'base'      => add_query_arg( 'paged', '%#%', add_query_arg( $filters, $base_url ) ),
				'format'    => '',
				'current'   => $page,
				'total'     => $total_pages,
				'prev_text' => '&laquo;',
				'next_text' => '&raquo;',
			] );
			echo wp_kses_post( is_string( $pagination ) ? $pagination : '' );
			?>
		</div></div>
	<?php endif; ?>
</div>
