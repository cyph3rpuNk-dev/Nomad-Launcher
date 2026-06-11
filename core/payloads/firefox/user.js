// Nomad Launcher — curated safe Firefox privacy profile (SPEC §5).
// Derived from arkenfox user.js <https://github.com/arkenfox/user.js>.
// Aggressive or site-breaking settings are intentionally excluded.

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
// Strict ETP otherwise breaks logins / checkout / embeds on major sites. Enable
// the BASELINE list ("Fix major site issues"): Mozilla un-blocks only a curated,
// publicly-tracked set (etp-exceptions.mozilla.org) of trackers essential for
// those sites to load — it does not broadly weaken protection and matches Nomad's
// "safe" goal (max privacy without breaking sites). Keep the CONVENIENCE list
// ("Fix minor site issues") OFF — it trades real protection for minor conveniences.
user_pref("privacy.trackingprotection.allow_list.baseline.enabled", true);
user_pref("privacy.trackingprotection.allow_list.convenience.enabled", false);

// --- HTTPS-only mode ---
user_pref("dom.security.https_only_mode", true);
user_pref("dom.security.https_only_mode_ever_enabled", true);

// --- Fingerprinting protection (safe — does not break sites) ---
user_pref("privacy.fingerprintingProtection", true);

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

// --- Toolbar & chrome UI ---
// Hide the empty-state bookmarks toolbar hint shown on new tab. Users who want
// the toolbar can re-enable it via View → Toolbars or by right-clicking the tab strip.
user_pref("browser.toolbars.bookmarks.visibility", "never");

// --- Floorp-specific UI (silently ignored by Firefox, Waterfox, LibreWolf) ---
// Floorp ships several non-stock UI surfaces enabled by default. They aren't
// harmful, but they clutter the launcher experience and the "Cubesoft (Sponsor)"
// tile on the custom new-tab page is paid placement. Disable all three so
// portable Floorp matches the chrome of stock Firefox.
user_pref("floorp.workspaces.enabled", false);
user_pref("floorp.panelSidebar.enabled", false);
// floorp.design.configs is a stringified JSON blob; disableFloorpStart=true
// turns off Floorp's "Floorp Start" dashboard and reverts about:newtab to the
// standard Firefox new-tab page (which honours the sponsored-tile prefs below).
user_pref("floorp.design.configs", "{\"uiCustomization\":{\"disableFloorpStart\":true}}");

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

// --- DNS over HTTPS (mode 2 = DoH with OS-DNS fallback) ---
user_pref("network.trr.mode", 2);

// --- Enhanced Tracking Protection ---
user_pref("privacy.trackingprotection.cryptomining.enabled", true);

// --- Windows taskbar Jump List (avoids recently-visited site traces on host) ---
user_pref("browser.taskbar.lists.enabled", false);

// --- Disk cache (avoids cached content traces on host) ---
user_pref("browser.cache.disk.enable", false);

// --- Sanitize on shutdown (clears ephemeral traces when the browser closes) ---
// Cookies and history are preserved so sessions and workflow survive restarts.
// Only _v2 prefs are set: Firefox 128+ ignores the legacy clearOnShutdown.*
// names entirely; the _v2 variants cover all release trains Nomad targets.
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.clearOnShutdown_v2.cache", true);
user_pref("privacy.clearOnShutdown_v2.cookiesAndStorage", false);
user_pref("privacy.clearOnShutdown_v2.downloads", true);
user_pref("privacy.clearOnShutdown_v2.formdata", true);
user_pref("privacy.clearOnShutdown_v2.browsingData", false);
user_pref("privacy.clearOnShutdown_v2.sessions", true);
