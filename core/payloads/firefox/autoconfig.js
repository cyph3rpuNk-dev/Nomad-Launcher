// Nomad Launcher Gecko autoconfig pointer.
//
// Tells Firefox / Floorp / Waterfox to load `nomad.cfg` from the install
// directory on startup, before any profile is loaded. Combined with the
// `lockPref()` directives in nomad.cfg, this gives us the same hardening
// posture that LibreWolf, Tor Browser, and Mozilla Enterprise use — far
// stronger than profile-level `user.js` which only applies once the
// profile has already loaded.
//
// nomad.cfg is derived from LibreWolf's official `librewolf.cfg`
// (https://codeberg.org/librewolf/settings, MPL-2.0).

// .cfg filename loaded by Gecko at startup (path cannot be changed)
pref("general.config.filename", "nomad.cfg");

// Plain-text .cfg (no obfuscation byte-shifting)
pref("general.config.obscure_value", 0);

// Keep the autoconfig sandbox enabled (default since Firefox 60)
pref("general.config.sandbox_enabled", true);
