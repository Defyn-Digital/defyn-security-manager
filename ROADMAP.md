# Defyn Security Manager — Roadmap

Internal development plan. Not shipped to WordPress.org (excluded from the
release zip in `.github/workflows/release.yml`).

---

## v1.0.0 — Shipped

Submitted to WordPress.org on 2026-05-17 (slug: `defyn-security-manager`).
Currently awaiting human review.

Features in this release:

- Hidden login URL (replaces `/wp-admin` + `/wp-login.php` with a custom slug)
- Configurable response for original-URL hitters: 404, redirect, fake login
- IP allowlist for the hidden slug
- Brute-force throttle with rolling window + admin "clear lockouts" button
- TOTP 2FA (RFC 6238) — Google Authenticator, Authy, 1Password, etc.
- 8 single-use backup codes per user
- Role-based 2FA enforcement
- REST + XML-RPC blocked for 2FA-required roles (closes a common bypass gap)
- Optional XML-RPC / REST hiding
- Time-window access (with cross-midnight handling + emergency bypass code)
- Activity log: every login, lockout, scan, settings change
- Email alerts (rate-limited)
- DSM_DISABLE kill switch for self-recovery

---

## v1.1.0 — Next iteration (post-WP.org approval)

Two main goals: a **new feature** (idle-session auto-logout) and a **UX
overhaul** that makes the plugin approachable for non-security-pro
administrators.

### New: Idle session timeout

Auto-logout after N minutes of admin inactivity. WordPress doesn't ship this
natively.

**Implementation outline:**
- JS file enqueued on `admin_enqueue_scripts`
- Listens for `mousemove`, `keydown`, `scroll`, `touchstart` (debounced)
- After N seconds idle, calls `wp_logout_url()` with the standard logout nonce
- Optional "Still there? Logging out in 30s" modal warning
- Server-side companion:
  - Settings field: idle minutes (default 15, range 1–120)
  - Role scope: all users / 2FA-required roles only / specific roles
  - Apply to: wp-admin only / wp-admin + frontend
- New activity-log event: `EVT_IDLE_LOGOUT`

**Open questions to decide at implementation time:**
- Default scope: 2FA-required roles only (more conservative) or all users?
- Default minutes: 15 (industry-typical) or 5 (Dan's original suggestion)?

### UI overhaul — Bundle A: First-run wizard + dashboard

The single biggest UX uplift. New users currently land on a settings page
with no guidance.

**First-run setup wizard** (triggers on plugin activation, skippable):
1. **Hidden URL** — pick slug, show preview, force "I've bookmarked this"
   checkbox before continuing
2. **Brute-force throttle** — recommended defaults preselected, slider for
   threshold/window/lockout
3. **2FA** — toggle site-wide, pick required roles, walk admin through
   enrolment right inside the wizard (QR + backup codes)
4. **Optional hardening** — IP allowlist, time window (clearly marked
   "skip if unsure")
5. **Recovery briefing** — generate emergency bypass code, copy-paste the
   `DSM_DISABLE` line, force "I've saved this somewhere" confirmation

**Dashboard landing page** (replaces settings-first default):
- Top-level menu click goes to Dashboard, not Settings
- Status cards:
  - Hidden URL: ✅ enabled, slug = X, copy-to-clipboard button
  - Throttle: ON / OFF, N active lockouts (link to clear), Y attempts
    blocked in last 24h
  - 2FA: M of N admins enrolled (with list of non-enrolled)
  - Last 7 days activity: small bar chart
- Smart recommendations card:
  - "⚠️ 1 admin hasn't enrolled in 2FA — send reminder"
  - "💡 You haven't set a time window — consider enabling it for
    overnight protection"
  - Dismissible per recommendation

### UI overhaul — Bundle B: In-context teaching

Across every existing screen, add the *why* not just the *what*.

- **Inline help icons** (?) on every setting field. Click opens a tooltip
  with: what it does, when to enable, what happens if off, example value.
- **"Recommended" badges** on safe defaults.
- **Per-tab introductions**: 1–2 paragraphs at the top of each tab —
  "What this protects against" + "How attackers exploit this when off".
- **Always-visible recovery sidebar**: right-hand column on every BE Security
  page with "🆘 Locked out?" + copy-paste `DSM_DISABLE` line + link to full
  recovery FAQ. So nobody panics.

### UI overhaul — Bundle C: Prevent self-lockouts

The two changes that most often save users from support tickets.

- **2FA enrolment nudge**: dismissible-per-user admin notice for admins in
  a 2FA-required role who haven't enrolled. Closes the chicken-and-egg gap
  where enabling enforcement immediately locks the only admin out.
- **Pre-flight "test my settings" button**: simulates a login attempt with
  current configuration before save, reports problems:
  - "Your current IP isn't on the allowlist — saving will lock you out"
  - "Current time is outside your time window — saving will lock you out"
  - "2FA is required but you haven't enrolled — enrol first then save"

### UI overhaul — Bundle D: Activity log polish

- Color-coded event types (red = failed login / lockout, amber = scan,
  green = login success, blue = settings change)
- Quick-filter pills above the table: Last 24h, Failed only, Admin actions,
  Lockouts, 2FA events
- Sparkline of attempts-per-hour at the top of the page
- Per-row tooltip explaining what each event type means + linking to the
  source action (e.g. "lockout" → link to throttle settings)
- Optional CSV export

---

## v1.2.0+ — Backlog

Ordered loosely by user-value-to-effort ratio. Not committed.

### Multisite support
Currently single-site only. The throttle table, activity log, and 2FA secrets
all need to become network-aware. Settings should support network-level
defaults + per-site overrides.

### WebAuthn / hardware-key 2FA
Second 2FA option alongside TOTP. YubiKey, Touch ID, Windows Hello, etc.
More secure (phishing-resistant) and faster than TOTP. Likely depends on a
new server-side WebAuthn library or vendor.

### Geo-IP allowlist
Country-level allow/deny in addition to IP-CIDR. Requires either a bundled
GeoLite2 DB (MaxMind) or a free public API (with rate limits).

### Slack / webhook alerts
In addition to email. Configurable webhook URL + per-event-type filter.
Templates for Slack, Discord, Mattermost.

### Login attempt analytics
A dedicated "Insights" page with charts: top attacking IPs over time,
most-targeted usernames, attack pattern detection (single-IP-many-users
vs many-IPs-one-user), exportable reports.

### Behind-proxy auto-detect
Currently the user has to define `DSM_TRUST_PROXY` in `wp-config.php`. Could
detect common proxy headers (`CF-Connecting-IP`, `True-Client-IP`) and offer
a UI toggle with an explicit "I confirm this site is behind a proxy" gate
(to avoid the spoofing risk).

### Login-page CAPTCHA
Optional reCAPTCHA / hCaptcha / Cloudflare Turnstile on the hidden login
form. Useful for sites that can't or won't use 2FA.

### REST application-password integration
Allow REST API access for 2FA-required roles when using WP application
passwords (which are independently per-app credentials and not bypassable
via UI). Currently we block all REST auth for those roles; this would be
a more nuanced policy.

### Pluggable storage backends
Activity log currently writes to a custom table. For high-traffic sites
this could become noisy. Pluggable backends: file (rotated), syslog, or
WP REST sink for sending to an external SIEM.

---

## Process notes

- Don't merge to `main` while WordPress.org review is in flight. Reviewer
  pulls from the submitted zip, not from GitHub, but staying still avoids
  any confusion.
- After v1.0.0 approval + SVN push, branch `develop` and do v1.1.0 work
  there. Merge to `main` + tag when ready to submit an update.
- WordPress.org updates: bump `Version:` header + `DSM_VERSION` constant +
  `Stable tag:` in readme.txt + `== Changelog ==` entry, then `svn ci` to
  the WP.org SVN repo. The GitHub release workflow still publishes a
  backup zip to GitHub Releases.
- Plugin Check should be re-run for every release before submitting.
