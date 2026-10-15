// Nomad Launcher — curated safe Waterfox privacy profile (SPEC §5).
// Derived from arkenfox user.js <https://github.com/arkenfox/user.js>.
// Waterfox engine versions change with upstream releases; preference support
// and effective behavior require separate runtime checks.

// --- Telemetry & data collection ---
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.server", "data:,");
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");
user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false);

// --- Updates (Nomad manages browser updates) ---
user_pref("app.update.auto", false);
user_pref("browser.shell.checkDefaultBrowser", false);

// --- Geolocation ---
user_pref("geo.enabled", false);

// --- Speculative connections & prefetching ---
user_pref("network.http.speculative-parallel-limit", 0);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);
user_pref("network.predictor.enabled", false);
user_pref("network.prefetch-next", false);

// --- WebRTC (restrict IP leakage without breaking calls) ---
user_pref("media.peerconnection.ice.default_address_only", true);

// --- Tracking protection ---
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);

// --- ETP WebCompat allow-lists ("Fix site issues" under Strict) ---
// Enable both major and minor site fixes. These exceptions can restore blocked
// content that may contain trackers; they do not change the selected ETP mode.
// Record the opt-in before Gecko's first-use migration disables both lists.
user_pref("privacy.trackingprotection.allow_list.hasMigratedCategoryPrefs", true);
user_pref("privacy.trackingprotection.allow_list.baseline.enabled", true);
user_pref("privacy.trackingprotection.allow_list.convenience.enabled", true);

// --- HTTPS-only mode ---
user_pref("dom.security.https_only_mode", true);
user_pref("dom.security.https_only_mode_ever_enabled", true);

// --- Fingerprinting protection ---
// Keep Nomad's existing Waterfox RFP choice; do not infer engine support
// from a historical ESR version or enable a second protection framework.
user_pref("privacy.resistFingerprinting", true);

// --- Search & URL bar ---
user_pref("browser.urlbar.speculativeConnect.enabled", false);
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);

// --- Session privacy ---
user_pref("browser.sessionstore.privacy_level", 2);

// --- Misc ---
user_pref("browser.send_pings", false);
user_pref("beacon.enabled", false);

// --- Safe Browsing (phones home to Google every ~30 min without this) ---
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.blockedURIs.enabled", false);
user_pref("browser.safebrowsing.provider.google4.gethashURL", "");
user_pref("browser.safebrowsing.provider.google4.updateURL", "");
user_pref("browser.safebrowsing.provider.mozilla.gethashURL", "");
user_pref("browser.safebrowsing.provider.mozilla.updateURL", "");
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.enabled", false);

// --- Captive portal detection ---
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);

// --- Activity Stream (sponsored tiles, Pocket, snippets) ---
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);
user_pref("browser.newtabpage.activity-stream.feeds.snippets", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includePocket", false);
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("browser.newtabpage.activity-stream.feeds.discoverystreamfeed", false);
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);

// --- Ping Centre ---
user_pref("browser.ping-centre.telemetry", false);

// --- Referrer (XOriginTrimmingPolicy trims to origin; safe for OAuth — unlike XOriginPolicy=2 which strips entirely) ---
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);

// --- DNS over HTTPS ---
// DNS transport/provider preferences are intentionally not set here or in
// Waterfox's shared autoconfig. Upstream 6.7.6 defaults to TRR-first (mode 2)
// with an oblivious HTTP relay; explicit profile choices remain authoritative.
// Mode 2 permits native DNS fallback. These settings alone do not prove traffic.

// --- Enhanced Tracking Protection ---
user_pref("privacy.trackingprotection.cryptomining.enabled", true);

// --- Windows taskbar Jump List (avoids recently-visited site traces on host) ---
user_pref("browser.taskbar.lists.enabled", false);

// --- Disk cache (avoids cached content traces on host) ---
user_pref("browser.cache.disk.enable", false);

// --- Sanitize on shutdown (clears ephemeral traces when the browser closes) ---
// Cookies and history are preserved so sessions and workflow survive restarts.
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.clearOnShutdown.cookies", false);
user_pref("privacy.clearOnShutdown.downloads", true);
user_pref("privacy.clearOnShutdown.formdata", true);
user_pref("privacy.clearOnShutdown.history", false);
user_pref("privacy.clearOnShutdown.sessions", true);
user_pref("privacy.clearOnShutdown.offlineApps", true);
