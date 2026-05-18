/**
 * Decoy-login form handler.
 *
 * Intercepts the form submit, reveals a fake "invalid credentials" message,
 * and prevents the POST from leaving the browser. The server discards any
 * POST anyway — this just stops the network request and presents a
 * realistic-looking response to whoever (or whatever) is trying to log in.
 *
 * Emitted via a manual <script src> tag (not wp_enqueue_script) because the
 * fake login renders outside the WordPress theme/enqueue pipeline.
 */
( function () {
	'use strict';
	document.addEventListener( 'DOMContentLoaded', function () {
		var form = document.querySelector( 'form' );
		var err  = document.getElementById( 'defsec-fake-err' );
		if ( ! form || ! err ) {
			return;
		}
		form.addEventListener( 'submit', function ( e ) {
			e.preventDefault();
			err.classList.add( 'visible' );
		} );
	} );
} )();
