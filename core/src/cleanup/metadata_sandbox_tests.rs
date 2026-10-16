//! Replay genuine Windows-created metadata under explicit fake-host roots only.
//! No browser, WER/Shell creation API, real host cleanup or networking is invoked.
use super::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, io::Write};

const BASE: &str = r"C:\NomadMetadataQualification";
fn token_valid(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn read_bounded(p: &Path, max: u64) -> Vec<u8> {
    crate::fs_safety::ensure_file(p).unwrap();
    assert!(p.is_file() && std::fs::metadata(p).unwrap().len() <= max);
    let b = std::fs::read(p).unwrap();
    assert!(b.len() as u64 <= max);
    b
}
fn hash(b: &[u8]) -> String {
    hex::encode_upper(Sha256::digest(b))
}
fn save(p: &Path, bytes: &[u8]) {
    crate::fs_safety::create_dir_all(p.parent().unwrap()).unwrap();
    crate::fs_safety::write_new(p, bytes).unwrap();
}
fn session() -> (PathBuf, String, String) {
    // Operational guard, not attestation against a hostile host or spoofed user.
    assert_eq!(
        std::env::var("USERNAME").unwrap(),
        "WDAGUtilityAccount",
        "Sandbox only"
    );
    assert_eq!(
        std::env::var("USERPROFILE").unwrap(),
        r"C:\Users\WDAGUtilityAccount",
        "Sandbox only"
    );
    assert_eq!(std::env::var("NOMAD_METADATA_OFFLINE").unwrap(), "1");
    let capture = std::env::var("NOMAD_METADATA_CAPTURE_TOKEN").unwrap();
    let run = std::env::var("NOMAD_METADATA_RUN_TOKEN").unwrap();
    assert!(token_valid(&capture) && token_valid(&run));
    let root = Path::new(BASE).join(&capture);
    crate::fs_safety::ensure_directory(&root).unwrap();
    assert_eq!(
        read_bounded(&root.join("SESSION-OWNER.txt"), 256),
        format!("Nomad offline Windows metadata qualification v1\n{capture}\n").as_bytes()
    );
    let exe = std::env::current_exe().unwrap();
    crate::fs_safety::ensure_file(&exe).unwrap();
    assert!(exe.starts_with(r"C:\NomadInput\Replay"));
    (root, capture, run)
}

struct CapturedMetadata {
    state_bytes: Vec<u8>,
    files: std::collections::HashMap<String, Vec<u8>>,
    scope: Scope,
}
fn read_captures(root: &Path, token: &str) -> CapturedMetadata {
    let state_bytes = read_bounded(&root.join("QUALIFICATION-INPUT.json"), 131_072);
    let state: Value = serde_json::from_slice(&state_bytes).unwrap();
    assert_eq!(state["schema"], 1);
    assert_eq!(state["token"], token);
    assert_eq!(state["operation"], "captured_shell_and_custom_wer");
    assert_eq!(state["networking"], "Disable");
    assert_eq!(state["active_nonloopback_interfaces"], 0);
    assert_eq!(state["default_routes"], 0);
    assert_eq!(state["browser_launched"], false);
    assert_eq!(state["dump_requested"], false);
    assert_eq!(state["wer_submit_flags"], 324);
    assert_eq!(state["wer_consent"], "NotAsked");
    let portable = root.join("Portable");
    let image = portable.join(format!("Browser/Nomad-owned-{token}.exe"));
    let foreign_image = root.join(format!("Foreign/Nomad-foreign-{token}.exe"));
    assert!(image.is_file() && foreign_image.is_file());
    crate::instance::ensure(&portable, "helium", true).unwrap();
    let scope = Scope::new(&portable, &image, "helium").unwrap();
    let entries = state["files"].as_array().unwrap();
    assert_eq!(entries.len(), 4);
    let mut names = HashSet::new();
    let mut captures = std::collections::HashMap::new();
    for e in entries {
        let name = e["name"].as_str().unwrap();
        assert!(
            matches!(
                name,
                "owned-recent.lnk"
                    | "foreign-recent.lnk"
                    | "owned-Report.wer"
                    | "foreign-Report.wer"
            ) && names.insert(name)
        );
        assert_eq!(e["unmodified"], true);
        let b = read_bounded(&root.join("Captures").join(name), MAX_METADATA_BYTES);
        assert_eq!(e["bytes"], b.len());
        assert_eq!(e["sha256"], hash(&b));
        match name {
            "owned-Report.wer" => {
                assert_eq!(e["encoding"], "UTF-16LE-BOM");
                assert_eq!(e["source_store"], "machine_queue");
                assert!(b.starts_with(&[0xff, 0xfe]));
                assert!(
                    report_application_path(&b).is_some_and(|p| report_matches_image(&p, &scope))
                );
            }
            "foreign-Report.wer" => assert!(
                report_application_path(&b).is_some_and(|p| !report_matches_image(&p, &scope))
            ),
            _ => {
                assert_eq!(e["source"], "SHAddToRecentDocs");
                assert_eq!(
                    e["link_flags"],
                    u32::from_le_bytes(b[20..24].try_into().unwrap())
                );
            }
        }
        captures.insert(name.to_owned(), b);
    }
    CapturedMetadata {
        state_bytes,
        files: captures,
        scope,
    }
}

fn write_result(root: &Path, run: &str, result: &Value) {
    let output = root.join(format!("REPLAY-{run}.json"));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)
        .unwrap();
    file.write_all(&serde_json::to_vec(&result).unwrap())
        .unwrap();
}

#[test]
#[ignore = "explicit offline Windows Sandbox metadata replay; never run on personal host stores"]
fn qualify_windows_metadata() {
    let (root, token, run) = session();
    let CapturedMetadata {
        state_bytes,
        files: captures,
        scope,
    } = read_captures(&root, &token);
    let portable = root.join("Portable");
    let image = portable.join(format!("Browser/Nomad-owned-{token}.exe"));
    let marker = portable.join("Nomad/instance.toml");
    let marker_before = read_bounded(&marker, 1024);
    // Preserve the source Recent folder depth for a stored relative path. Copies
    // are otherwise unchanged; unknown/discordant metadata must still be kept.
    let host = root.join(format!("FakeHost-{run}"));
    assert!(!host.exists(), "Never reuse a previous replay fixture");
    let recent = host.join("AppData/Microsoft/Windows/Recent");
    let own_link = recent.join("owned.lnk");
    let foreign_link = recent.join("foreign.lnk");
    save(&own_link, &captures["owned-recent.lnk"]);
    save(&foreign_link, &captures["foreign-recent.lnk"]);
    let owned_document = portable.join(format!("Nomad-owned-{token}.txt"));
    let target_before =
        crate::shell_link::owned_target(&captures["owned-recent.lnk"], &own_link, &scope.launcher);
    let target_corroborated =
        target_before.as_ref() == Some(&std::fs::canonicalize(&owned_document).unwrap());
    let mut own_reports = Vec::new();
    let mut foreign_reports = Vec::new();
    for store in ["Local", "ProgramData"] {
        for queue in ["ReportQueue", "ReportArchive"] {
            let parent = host.join(store).join("Microsoft/Windows/WER").join(queue);
            let own = parent.join("owned");
            let foreign = parent.join("foreign");
            save(&own.join("Report.wer"), &captures["owned-Report.wer"]);
            save(
                &own.join("public-attachment.txt"),
                b"Public authored attachment; no memory dump",
            );
            save(&foreign.join("Report.wer"), &captures["foreign-Report.wer"]);
            save(
                &foreign.join("public-attachment.txt"),
                b"Public unrelated attachment sentinel",
            );
            own_reports.push(own);
            foreign_reports.push(foreign);
        }
    }
    let shared = host.join("Local/CrashDumps/public-inert.dmp");
    save(
        &shared,
        b"Public inert standalone dump sentinel; not a memory dump",
    );
    let sentinel = read_bounded(&shared, 1024);
    let attempt_completed = scrub_fixture(&portable, &image, "helium", &host);
    let own_removed = !own_link.exists();
    let own_reports_removed = own_reports.iter().all(|p| !p.exists());
    let foreign_link_preserved =
        read_bounded(&foreign_link, MAX_METADATA_BYTES) == captures["foreign-recent.lnk"];
    let foreign_reports_preserved = foreign_reports.iter().all(|p| {
        read_bounded(&p.join("Report.wer"), MAX_METADATA_BYTES) == captures["foreign-Report.wer"]
            && read_bounded(&p.join("public-attachment.txt"), 1024)
                == b"Public unrelated attachment sentinel"
    });
    let shared_preserved = read_bounded(&shared, 1024) == sentinel;
    let sources_unchanged = captures
        .iter()
        .all(|(n, b)| read_bounded(&root.join("Captures").join(n), MAX_METADATA_BYTES) == *b);
    let marker_unchanged = read_bounded(&marker, 1024) == marker_before;
    let repeated_completed = scrub_fixture(&portable, &image, "helium", &host);
    let retry_preserved = read_bounded(&foreign_link, MAX_METADATA_BYTES)
        == captures["foreign-recent.lnk"]
        && foreign_reports.iter().all(|p| {
            read_bounded(&p.join("Report.wer"), MAX_METADATA_BYTES)
                == captures["foreign-Report.wer"]
        })
        && read_bounded(&shared, 1024) == sentinel;
    let result = json!({
        "schema":1,"capture_token":token,"run_token":run,
        "qualification_input_sha256":hash(&state_bytes),
        "attempt_completed":attempt_completed,"repeat_attempt_completed":repeated_completed,
        "owned_recent_target_corroborated":target_corroborated,"owned_recent_removed":own_removed,
        "foreign_recent_preserved":foreign_link_preserved,"owned_wer_copies_removed":own_reports_removed,
        "owned_wer_copy_count":own_reports.len(),"foreign_wer_copies_preserved":foreign_reports_preserved,
        "standalone_sentinel_preserved":shared_preserved,"original_captures_unchanged":sources_unchanged,
        "marker_unchanged":marker_unchanged,"repeat_preserved_unrelated":retry_preserved,
        "observed":if own_removed && own_reports_removed {"scoped_replay_pass"} else {"cleanup_gap_observed"},
        "scope":"Unmodified Windows Shell Recent and custom noncritical queued WER metadata, replayed under explicitly owned fake-host roots only. Four queue/archive copies do not establish four natural crash variants or live WER activity. No browser, WER API, network or real host cleanup invoked by this replayer."
    });
    write_result(&root, &run, &result);
    assert!(
        attempt_completed
            && repeated_completed
            && target_corroborated
            && own_removed
            && own_reports_removed
            && foreign_link_preserved
            && foreign_reports_preserved
            && shared_preserved
            && sources_unchanged
            && marker_unchanged
            && retry_preserved,
        "Scoped replay did not qualify; preserve selected result and original metadata"
    );
}
