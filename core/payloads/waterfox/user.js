// Nomad Launcher — curated safe Waterfox privacy profile (SPEC §5).
// Derived from arkenfox user.js <https://github.com/arkenfox/user.js>.
// Waterfox is based on Firefox ESR 115; aggressive or site-breaking settings
// are intentionally excluded.

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

// --- HTTPS-only mode ---
user_pref("dom.security.https_only_mode", true);
user_pref("dom.security.https_only_mode_ever_enabled", true);

// --- Fingerprinting protection ---
// privacy.fingerprintingProtection requires Firefox 119+; Waterfox ESR 115
// uses the older privacy.resistFingerprinting API instead.
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
// Intentionally not set: Waterfox defaults to DNS-over-Oblivious-HTTP (DoOH),
// which is stronger than standard DoH (mode 2) — the intermediary proxy means
// the resolver never sees the user's IP. Overriding trr.mode would downgrade
// that to plain DoH; we defer to Waterfox's own, superior DNS privacy posture.

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
