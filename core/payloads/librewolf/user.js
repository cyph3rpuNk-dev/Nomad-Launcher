// Nomad Launcher — minimal LibreWolf privacy profile (SPEC §5).
//
// LibreWolf already ships arkenfox-equivalent hardening (verified against its
// librewolf.cfg): telemetry locked off, Safe Browsing off, Strict ETP
// (browser.contentblocking.category = "strict"), privacy.resistFingerprinting
// on, HTTPS-only on, disk cache off, prefetch/search-suggestions off,
// Pocket/Activity-Stream off, sessionstore privacy_level 2, referrer trimming,
// and app-update locked off. Applying Nomad's full arkenfox user.js there is
// redundant — almost every pref is a no-op (many are lockPref'd in
// librewolf.cfg, so Nomad couldn't override them even if it wanted to).
//
// This file keeps ONLY the genuine additions LibreWolf does not already make;
// everything else is deferred to LibreWolf's own (stronger or equal) defaults.
// The full profile still lives in payloads/firefox/user.js for Firefox/Floorp.

// --- DNS over HTTPS ---
// LibreWolf ships DoH OFF (network.trr.mode = 5, "let the user choose") and, when
// enabled, defaults to Quad9's No-Filtering endpoint. Nomad enables DoH (mode 2 =
// DoH with OS-DNS fallback) and points it at Quad9's MALWARE-BLOCKING endpoint —
// the documented DNS-level substitute for the disabled browser Safe Browsing
// (README "Trade-offs"). Privacy is identical to the No-Filtering endpoint; it
// just refuses known-malicious domains. (Oblivious DoH, like Waterfox ships, is
// not configurable in mainline Gecko — Mozilla removed ODoH in favour of OHTTP,
// which is not a user-selectable resolver.) This is the biggest divergence from
// stock LibreWolf and the main reason this file is not empty.
user_pref("network.trr.mode", 2);
user_pref("network.trr.uri", "https://dns.quad9.net/dns-query");

// --- Geolocation ---
// LibreWolf disables the OS location providers but not the geolocation API
// itself; geo.enabled is unset there. Disable the API outright.
user_pref("geo.enabled", false);

// --- Network prediction (not set by LibreWolf) ---
user_pref("network.predictor.enabled", false);

// --- WebRTC ---
// LibreWolf leaves media.peerconnection.ice.default_address_only = false.
// Restrict it to the default public interface. When [hardening] disable_webrtc
// = true (the default) the launcher additionally appends
// media.peerconnection.enabled = false, fully disabling WebRTC.
user_pref("media.peerconnection.ice.default_address_only", true);

// --- Hyperlink auditing & beacons (not set by LibreWolf) ---
user_pref("browser.send_pings", false);
user_pref("beacon.enabled", false);

// --- Windows taskbar Jump List (avoids recently-visited site traces on host) ---
user_pref("browser.taskbar.lists.enabled", false);

// --- Bookmarks toolbar: match the rest of the Nomad suite (LibreWolf=always) ---
user_pref("browser.toolbars.bookmarks.visibility", "never");

// --- Sanitize on shutdown ---
// LibreWolf enables sanitizeOnShutdown but does not configure the granular
// behaviour. Clear ephemeral traces on exit; preserve cookies and history so
// sessions and workflow survive restarts.
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.clearOnShutdown.cookies", false);
user_pref("privacy.clearOnShutdown.downloads", true);
user_pref("privacy.clearOnShutdown.formdata", true);
user_pref("privacy.clearOnShutdown.history", false);
user_pref("privacy.clearOnShutdown.sessions", true);
user_pref("privacy.clearOnShutdown.offlineApps", true);
// Firefox 128+ renamed the prefs; set both to cover all release trains.
user_pref("privacy.clearOnShutdown_v2.cache", true);
user_pref("privacy.clearOnShutdown_v2.cookiesAndStorage", false);
user_pref("privacy.clearOnShutdown_v2.downloads", true);
user_pref("privacy.clearOnShutdown_v2.formdata", true);
user_pref("privacy.clearOnShutdown_v2.browsingData", false);
user_pref("privacy.clearOnShutdown_v2.sessions", true);
