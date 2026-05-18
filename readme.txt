=== Defyn Security Manager ===
Contributors: defyndigital
Tags: hide login, security, brute force, two factor, login url
Requires at least: 6.2
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Hide your WordPress login behind a custom URL. Throttle brute-force attempts, enforce 2FA, restrict by IP and time, audit every login.

== Description ==

Defyn Security Manager hardens the WordPress login surface by hiding it behind a URL of your choice, then adding layered protection around it.

**Hide the login URL**

* Replace `/wp-admin` and `/wp-login.php` with any slug you pick — e.g. `your-site.com/secret-door`.
* Configure what attackers see when they probe the originals: a clean 404 (recommended), a redirect to any URL, or a decoy login that always fails.
* Restrict the new URL to specific IPs or CIDR ranges if you want.

**Brute-force protection**

* Automatic IP lockout after configurable failed attempts inside a rolling window.
* Defaults: 5 attempts within 15 minutes → 30-minute lockout. All thresholds adjustable.
* One-click "clear all lockouts" button in the admin if you ever need to reset.

**Two-factor authentication (TOTP)**

* RFC 6238 — compatible with Google Authenticator, Authy, 1Password, Microsoft Authenticator, Bitwarden, and any other TOTP app.
* Per-user enrolment with a QR code rendered server-side (no third-party QR service).
* Eight single-use backup codes stored as one-way hashes.
* Enforceable per role: pick which roles are required to use 2FA before they can log in.

**Time-window access**

* Only allow logins during the days and hours you choose, in your site's timezone.
* Windows that cross midnight are handled (e.g. 22:00–06:00 for overnight ops).
* Optional emergency bypass code lets a trusted admin override the window when needed. The bypass code is stored as a hash so a database leak doesn't reveal it.

**Other auth endpoints**

* Optionally hide `/xmlrpc.php` (safe for most modern sites).
* Optionally hide `/wp-json/` REST API (only enable if you know your site doesn't need REST — Gutenberg depends on it).
* Authenticated REST and XML-RPC requests for users in a 2FA-required role are always blocked, even when those endpoints stay reachable — closes a common 2FA-bypass gap.

**Activity log and email alerts**

* Custom database table records every login attempt, lockout, scan of `/wp-admin`, 2FA event, and settings change.
* Filter the log by event type or IP. Configurable retention (1–365 days).
* Opt-in email alerts for lockouts, scans of original URLs, and successful logins from new IPs. Rate-limited so an attacker can't flood your inbox.

**Recovery**

If you ever lock yourself out, define `DEFSEC_DISABLE` in `wp-config.php` to bypass all interception until you can fix the cause. The plugin shows a persistent yellow notice in the admin while the kill switch is active so you don't forget to remove it.

== Installation ==

1. WordPress admin → **Plugins → Add New → Search** for "Defyn Security Manager".
2. Click **Install Now**, then **Activate**.
3. Go to **Defyn Security → Settings → Hidden URL** and either keep the random slug the plugin generated for you, or change it to something memorable.
4. **Bookmark the hidden URL right now** — you'll lose access to `/wp-admin` the moment you save settings, and the bookmark is how you log back in.

Recommended next steps:

* **Defyn Security → Settings → Security**: turn on the throttle (it's on by default with sensible thresholds).
* **Defyn Security → Settings → Two-Factor**: enable 2FA across the site and require it for the Administrator role. Each admin then enrols from their **Users → Profile** page.

== Frequently Asked Questions ==

= I locked myself out. How do I recover? =

Add `define( 'DEFSEC_DISABLE', true );` to your site's `wp-config.php`. That bypasses all interception, so `/wp-admin` and `/wp-login.php` work like a vanilla WordPress install. Log in, fix the cause (clear the throttle, disable 2FA for your user, etc.), then remove the line from `wp-config.php`.

If you can't edit `wp-config.php`: rename the plugin folder via SFTP from `defyn-security-manager` to `defyn-security-manager.disabled`. WordPress will silently deactivate it on the next page load. Your settings and 2FA data are preserved; rename back to re-enable.

= Does it work behind Cloudflare or a load balancer? =

Yes. Define `DEFSEC_TRUST_PROXY` in `wp-config.php` so the plugin honors `CF-Connecting-IP` / `X-Real-IP` / `X-Forwarded-For` for client-IP detection. Only enable this when you're actually behind a known proxy — otherwise attackers can spoof their IP.

= Which authenticator apps are supported for 2FA? =

Any RFC 6238 TOTP app: Google Authenticator, Authy, 1Password, Microsoft Authenticator, Bitwarden, and most others. The plugin renders a QR code you can scan, or you can copy the secret manually.

= I lost my phone. How do I recover 2FA access? =

If you saved your backup codes when you enrolled, enter one of them in place of a 6-digit code at login. Each backup code works once.

If you didn't save backup codes: ask another administrator to disable 2FA on your user via **Users → All Users → your user → Edit**. If you're the only administrator, use the `DEFSEC_DISABLE` recovery path above.

= Can I use this on a multisite network? =

Single-site activation only for v1.0. Multisite support is on the roadmap.

= Does the plugin call home for any reason? =

No. Defyn Security Manager makes no outbound HTTP requests except the standard WordPress.org update check that WordPress itself performs for all installed plugins. None of your site data leaves your server.

= What about the REST API and XML-RPC? =

By default both work normally. For users in a role that requires 2FA, the plugin blocks REST and XML-RPC authentication with a clear error — those endpoints can't prompt for a TOTP code, so allowing them would let users bypass 2FA. You can also opt to hide either endpoint entirely under **Settings → Hidden URL**.

== Screenshots ==

1. Hidden URL settings — choose your slug and decide what /wp-admin shows to attackers.
2. Brute-force throttle settings, with the "Clear all lockouts" button when active.
3. Two-factor enrolment page — scan the QR code with any TOTP app.
4. Activity log dashboard with event filtering.
5. Time-window access controls with optional emergency bypass code.

== Changelog ==

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.0.0 =
First public release.
