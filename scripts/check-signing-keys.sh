#!/usr/bin/env bash
#
# Checks that every embedded signing key still contains the (sub)key that
# upstream is currently signing releases with.
#
# Why this exists: the keys in core/keys/ are point-in-time snapshots of keys
# that gain subkeys over time. Upstreams sign with a signing subkey rather than
# the primary, and they add new subkeys without changing the primary. A snapshot
# taken before such an addition still parses and still has the right primary, so
# every local check passes, but it no longer contains the subkey that signed the
# release and verification fails outright.
#
# That is not hypothetical. Between v1.0.5 and v1.0.6 Mozilla added subkey
# 827E658608679618CD349F93678E455D76767AA3, and Nomad's snapshot predated it, so
# Nomad-Firefox.exe and Nomad-Firefox-ESR.exe could not install or update at
# all. Nothing in the repository could detect it: the only signal was a user
# reporting that the launcher failed.
#
# The check fetches the signature upstream is publishing now (a few hundred
# bytes, never the package itself), reads the issuer key id out of it, and
# confirms that id is present in the embedded key. It deliberately does not
# fetch or update the key material: refreshing a trust anchor is a human
# decision, and an automated commit of a downloaded public key would defeat the
# point of pinning one.
#
# Usage: scripts/check-signing-keys.sh
# Exits non-zero if any embedded key no longer covers its upstream signer.

set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail=0

py() { command -v python3 >/dev/null 2>&1 && python3 "$@" || python "$@"; }

# Reads a value out of a JSON document on stdin, given a python expression
# operating on `d`. Avoids a jq dependency, which Git Bash does not ship.
json() { py -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

# Every key id in an armored public key file, primary and subkeys alike.
key_ids() {
    gpg --show-keys --with-colons "$1" 2>/dev/null |
        awk -F: '$1 == "pub" || $1 == "sub" { print toupper($5) }'
}

# The issuer key id of an armored detached signature.
sig_issuer() {
    gpg --list-packets "$1" 2>/dev/null |
        sed -n 's/.*keyid \([0-9A-Fa-f]\{16\}\).*/\1/p' |
        head -1 |
        tr '[:lower:]' '[:upper:]'
}

# check <label> <key file> <signature file>
check() {
    local label="$1" keyfile="$2" sigfile="$3"
    local issuer ids

    if [ ! -s "$sigfile" ]; then
        echo "::error::${label}: no upstream signature was fetched, so key coverage could not be checked"
        fail=1
        return
    fi

    issuer="$(sig_issuer "$sigfile")"
    if [ -z "$issuer" ]; then
        echo "::error::${label}: could not read an issuer key id out of the upstream signature"
        fail=1
        return
    fi

    ids="$(key_ids "$keyfile")"
    if [ -z "$ids" ]; then
        echo "::error::${label}: ${keyfile#"$repo_root"/} contains no readable keys"
        fail=1
        return
    fi

    if printf '%s\n' "$ids" | grep -qxF "$issuer"; then
        echo "ok       ${label}: signed with ${issuer}, present in ${keyfile#"$repo_root"/}"
    else
        echo "::error::${label}: upstream now signs with key id ${issuer}, which is not in ${keyfile#"$repo_root"/}. That launcher cannot verify any download. Refresh the key from upstream's published key file and confirm the primary fingerprint is unchanged before committing it."
        echo "         key ids currently embedded: $(printf '%s ' $ids)"
        fail=1
    fi
}

echo "== Mozilla (Firefox, Firefox ESR) =="
if curl -sSfL --retry 3 https://product-details.mozilla.org/1.0/firefox_versions.json \
    -o "$tmp/firefox_versions.json"; then
    for field in LATEST_FIREFOX_VERSION FIREFOX_ESR; do
        version="$(json "d['$field']" < "$tmp/firefox_versions.json")"
        if [ -z "$version" ]; then
            echo "::error::Mozilla: could not resolve ${field} from product-details"
            fail=1
            continue
        fi
        sig="$tmp/mozilla-${field}.asc"
        if curl -sSfL --retry 3 \
            "https://ftp.mozilla.org/pub/firefox/releases/${version}/SHA256SUMS.asc" -o "$sig"; then
            check "Firefox ${version}" "$repo_root/core/keys/firefox.asc" "$sig"
        else
            echo "::error::Firefox ${version}: SHA256SUMS.asc could not be fetched"
            fail=1
        fi
    done
else
    echo "::error::Mozilla: product-details could not be fetched"
    fail=1
fi

echo "== Mullvad Browser =="
if curl -sSfL --retry 3 -H 'Accept: application/vnd.github+json' \
    https://api.github.com/repos/mullvad/mullvad-browser/releases/latest \
    -o "$tmp/mullvad-release.json"; then
    url="$(json "next((a['browser_download_url'] for a in d['assets'] if a['name'].endswith('.asc') and 'windows' in a['name']), '')" \
        < "$tmp/mullvad-release.json")"
    if [ -n "$url" ] && curl -sSfL --retry 3 "$url" -o "$tmp/mullvad.asc"; then
        check "Mullvad Browser" "$repo_root/core/keys/mullvad.asc" "$tmp/mullvad.asc"
    else
        echo "::error::Mullvad Browser: no Windows .asc asset on the latest release"
        fail=1
    fi
else
    echo "::error::Mullvad Browser: release metadata could not be fetched"
    fail=1
fi

echo "== gorhill / uBlock Origin =="
# gorhill signs git history rather than the release assets, so the signature
# comes from the object the tag points at. This mirrors
# fetch_gorhill_tag_verification in core/src/browsers/ungoogled.rs: gorhill uses
# lightweight tags, which point straight at a signed commit, and annotated tags
# are handled as a forward-compatibility case.
ubo_api="https://api.github.com/repos/gorhill/uBlock"
if curl -sSfL --retry 3 -H 'Accept: application/vnd.github+json' \
    "${ubo_api}/releases/latest" -o "$tmp/ubo-release.json"; then
    tag="$(json "d['tag_name']" < "$tmp/ubo-release.json")"
    if curl -sSfL --retry 3 -H 'Accept: application/vnd.github+json' \
        "${ubo_api}/git/refs/tags/${tag}" -o "$tmp/ubo-ref.json"; then
        obj_type="$(json "d['object']['type']" < "$tmp/ubo-ref.json")"
        obj_sha="$(json "d['object']['sha']" < "$tmp/ubo-ref.json")"
        case "$obj_type" in
            commit)
                url="${ubo_api}/commits/${obj_sha}"
                expr="d.get('commit', {}).get('verification', {}).get('signature') or ''"
                ;;
            tag)
                url="${ubo_api}/git/tags/${obj_sha}"
                expr="d.get('verification', {}).get('signature') or ''"
                ;;
            *)
                url=""
                ;;
        esac
        if [ -n "$url" ] && curl -sSfL --retry 3 -H 'Accept: application/vnd.github+json' \
            "$url" -o "$tmp/ubo-obj.json"; then
            json "$expr" < "$tmp/ubo-obj.json" > "$tmp/gorhill.asc"
            check "uBlock Origin ${tag}" "$repo_root/core/keys/gorhill.asc" "$tmp/gorhill.asc"
        else
            echo "::error::uBlock Origin ${tag}: tag points at an unexpected object type '${obj_type}'"
            fail=1
        fi
    else
        echo "::error::uBlock Origin ${tag}: tag ref could not be fetched"
        fail=1
    fi
else
    echo "::error::uBlock Origin: release metadata could not be fetched"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo
    echo "One or more embedded signing keys no longer cover their upstream signer."
    echo "A launcher in that state fails every install and update, and the failure"
    echo "is only visible to whoever runs it."
    exit 1
fi

echo
echo "All embedded signing keys still cover the key upstream is signing with."
