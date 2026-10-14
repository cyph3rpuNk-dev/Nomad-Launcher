//! Explicit, ignored native checks restricted to a disposable guest fixture.
//! No browser/registry action and no real host roots are passed to cleanup.
use super::*;
use std::{
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
const OWNER: &str = "Nomad disposable recovery qualification v1";
const PAYLOAD: &[u8] = b"Public inert Nomad native-binding qualification payload v1";
const BASE: &str = r"C:\NomadRecoveryQualification";
fn valid_token(token: &str) -> bool {
    token.len() == 32
        && token
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn session() -> PathBuf {
    // Operational guard, not an attestation against a malicious host/user.
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
    let token = std::env::var("NOMAD_RECOVERY_FIXTURE_TOKEN").unwrap();
    assert!(valid_token(&token));
    let root = Path::new(BASE).join(&token);
    crate::fs_safety::ensure_directory(&root).unwrap();
    assert_eq!(
        std::fs::read_to_string(root.join("SESSION-OWNER.txt")).unwrap(),
        format!("{OWNER}\n{token}\n")
    );
    let exe = std::env::current_exe().unwrap();
    crate::fs_safety::ensure_file(&exe).unwrap();
    assert!(exe.starts_with(Path::new(r"C:\NomadInput")) || exe.starts_with(&root));
    root
}
struct Fixture {
    root: PathBuf,
    image: PathBuf,
    host: PathBuf,
    own_report: PathBuf,
    foreign_report: PathBuf,
    sentinel: PathBuf,
}
impl Fixture {
    fn create(session: &Path, name: &str) -> Self {
        assert!(matches!(name, "running" | "interrupted" | "path-change"));
        let root = session.join(name).join("portable");
        let image = root.join("Browser/Nomad-Recovery-Qualification-Probe.exe");
        crate::fs_safety::create_dir_all(image.parent().unwrap()).unwrap();
        assert!(!image.exists(), "Never overwrite an earlier qualification");
        std::fs::copy(std::env::current_exe().unwrap(), &image).unwrap();
        crate::instance::ensure(&root, "helium", true).unwrap();
        let host = session.join(name).join("fake-host");
        for store in ["AppData", "Local", "ProgramData"] {
            crate::fs_safety::create_dir_all(host.join(store)).unwrap();
        }
        let own_report = host.join("Local/Microsoft/Windows/WER/ReportQueue/owned");
        crate::fs_safety::create_dir_all(&own_report).unwrap();
        crate::fs_safety::write_new(
            &own_report.join("Report.wer"),
            format!("AppPath={}\r\n", image.display()).as_bytes(),
        )
        .unwrap();
        crate::fs_safety::write_new(
            &own_report.join("memory.dmp"),
            b"INERT authored report attachment",
        )
        .unwrap();
        let foreign_image = session.join(name).join("foreign/desktop.exe");
        crate::fs_safety::create_dir_all(foreign_image.parent().unwrap()).unwrap();
        crate::fs_safety::write_new(&foreign_image, b"inert foreign executable marker").unwrap();
        let foreign_report = host.join("ProgramData/Microsoft/Windows/WER/ReportQueue/foreign");
        crate::fs_safety::create_dir_all(&foreign_report).unwrap();
        crate::fs_safety::write_new(
            &foreign_report.join("Report.wer"),
            format!("AppPath={}\r\n", foreign_image.display()).as_bytes(),
        )
        .unwrap();
        let sentinel = host.join("Local/CrashDumps/shared.dmp");
        crate::fs_safety::create_dir_all(sentinel.parent().unwrap()).unwrap();
        crate::fs_safety::write_new(&sentinel, b"INERT shared-dump sentinel").unwrap();
        Self {
            root,
            image,
            host,
            own_report,
            foreign_report,
            sentinel,
        }
    }
    fn arm(&self) {
        let _install = crate::install::InstanceLock::acquire(&self.root.join("Browser")).unwrap();
        arm_with(&self.root, &self.image, "helium", &NativeBinding).unwrap();
    }
    fn replay(&self) -> usize {
        let _install = crate::install::InstanceLock::acquire(&self.root.join("Browser")).unwrap();
        replay_with(
            &self.root,
            "helium",
            &NativeBinding,
            |s| crate::cleanup_process::probe(&s.launcher, &s.browser_exe),
            |s| crate::cleanup::scrub_fixture(&s.launcher, &s.browser_exe, "helium", &self.host),
        )
        .unwrap()
    }
    fn pending(&self) {
        assert_eq!(records(&self.root).unwrap().len(), 1);
        assert!(self.own_report.join("Report.wer").exists());
        self.preserved();
    }
    fn preserved(&self) {
        assert!(self.foreign_report.join("Report.wer").exists());
        assert_eq!(
            std::fs::read(&self.sentinel).unwrap(),
            b"INERT shared-dump sentinel"
        );
    }
}
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill(); // Only the exact inert child created below.
        }
        let _ = self.0.wait();
    }
}
fn helper(image: &Path, name: &str, case: &str) -> OwnedChild {
    assert!(matches!(case, "running" | "interrupted"));
    let child = Command::new(image)
        .args([
            "--exact",
            name,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("NOMAD_RECOVERY_CASE", case)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    OwnedChild(child)
}
fn ready(session: &Path, case: &str, child: &mut OwnedChild) {
    let path = session.join(case).join("ready.txt");
    let deadline = Instant::now() + Duration::from_secs(15);
    while !path.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "Inert helper exited before readiness"
        );
        assert!(Instant::now() < deadline, "Inert helper readiness timeout");
        thread::sleep(Duration::from_millis(50));
    }
}
fn helper_context() -> (PathBuf, String) {
    let session = session();
    let case = std::env::var("NOMAD_RECOVERY_CASE").unwrap();
    assert!(matches!(case.as_str(), "running" | "interrupted"));
    (session, case)
}
fn signal_and_wait(session: &Path, case: &str) {
    crate::fs_safety::write_new(&session.join(case).join("ready.txt"), b"inert helper ready")
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(45);
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
}
#[test]
#[ignore = "disposable Sandbox native qualification only; operational guest guards required"]
fn helper_wait() {
    let (session, case) = helper_context();
    signal_and_wait(&session, &case);
}
#[test]
#[ignore = "disposable Sandbox inert worker; intentionally terminated by its parent fixture"]
fn helper_interrupted_worker() {
    let (session, case) = helper_context();
    assert_eq!(case, "interrupted");
    let root = session.join(&case).join("portable");
    let image = std::env::current_exe().unwrap();
    let install = crate::install::InstanceLock::acquire(&root.join("Browser")).unwrap();
    arm_with(&root, &image, "helium", &NativeBinding).unwrap();
    let _coordinator = CleanupSession::acquire(&root, &image, "helium")
        .unwrap()
        .unwrap();
    drop(install);
    signal_and_wait(&session, &case);
}
#[test]
#[ignore = "explicit Sandbox suite; never run on the host or in the normal gate"]
fn qualify_native_recovery() {
    let session = session();
    let protected = NativeBinding.seal(PAYLOAD).unwrap();
    assert_eq!(NativeBinding.open(&protected).unwrap(), PAYLOAD);
    assert!(!protected.windows(PAYLOAD.len()).any(|part| part == PAYLOAD));
    let mut tampered = protected.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(NativeBinding.open(&tampered).is_err());
    assert!(NativeBinding.open(b"not a DPAPI blob").is_err());
    crate::fs_safety::write_new(&session.join("native-protected.bin"), &protected).unwrap();
    // Separately export machine-scope public payload to distinguish the layers
    // if a later disposable context is genuinely backed by different keys.
    let machine = dpapi(PAYLOAD, true, true).unwrap();
    assert_eq!(dpapi(&machine, false, false).unwrap(), PAYLOAD);
    crate::fs_safety::write_new(&session.join("machine-protected.bin"), &machine).unwrap();

    qualify_running_image(&session);
    qualify_interrupted_worker(&session);
    qualify_changed_path(&session);
    let results = serde_json::json!({
        "schema": 1, "native_round_trip": true, "native_tamper_refused": true,
        "malformed_blob_refused": true, "running_image_preserved": true,
        "same_name_foreign_image_unknown": true, "cross_process_record_recovered": true,
        "terminated_worker_lock_released": true, "unavailable_image_preserved": true,
        "moved_scope_preserved": true, "attributed_fixture_reports_removed": true,
        "foreign_report_and_shared_dump_preserved": true,
        "scope": "inert fake-host fixtures; not a production browser/watcher/crash/power-loss test"
    });
    crate::fs_safety::write_new(
        &session.join("native-results.json"),
        &serde_json::to_vec_pretty(&results).unwrap(),
    )
    .unwrap();
    println!("NATIVE RECOVERY QUALIFICATION PASSED; inert fixtures only; retain output for host verification.");
}
fn qualify_running_image(session: &Path) {
    let running = Fixture::create(session, "running");
    running.arm();
    let scope = Scope::new(&running.root, &running.image, "helium").unwrap();
    assert_eq!(
        crate::cleanup_process::probe(&scope.launcher, &scope.browser_exe),
        Presence::Idle
    );
    let mut child = helper(
        &running.image,
        "cleanup_recovery::sandbox_tests::helper_wait",
        "running",
    );
    ready(session, "running", &mut child);
    assert_eq!(
        crate::cleanup_process::probe(&scope.launcher, &scope.browser_exe),
        Presence::Running
    );
    assert_eq!(running.replay(), 0);
    running.pending();
    drop(child);
    assert_eq!(
        crate::cleanup_process::probe(&scope.launcher, &scope.browser_exe),
        Presence::Idle
    );
    std::fs::remove_file(session.join("running/ready.txt")).unwrap();
    let foreign_image = session
        .join("running/foreign")
        .join(running.image.file_name().unwrap());
    std::fs::copy(&running.image, &foreign_image).unwrap();
    let mut outside = helper(
        &foreign_image,
        "cleanup_recovery::sandbox_tests::helper_wait",
        "running",
    );
    ready(session, "running", &mut outside);
    assert_eq!(
        crate::cleanup_process::probe(&scope.launcher, &scope.browser_exe),
        Presence::Unknown
    );
    assert_eq!(running.replay(), 0);
    running.pending();
    drop(outside);
    assert_eq!(running.replay(), 1);
    assert!(!running.own_report.exists());
    running.preserved();
}
fn qualify_interrupted_worker(session: &Path) {
    let interrupted = Fixture::create(session, "interrupted");
    let mut worker = helper(
        &interrupted.image,
        "cleanup_recovery::sandbox_tests::helper_interrupted_worker",
        "interrupted",
    );
    ready(session, "interrupted", &mut worker);
    interrupted.pending();
    assert_eq!(interrupted.replay(), 0); // Live coordinator lock owns this intent.
    worker.0.kill().unwrap();
    worker.0.wait().unwrap();
    drop(worker);
    // A record written in the child must decrypt in this fresh reader process;
    // OS lock release on termination must permit coordinator acquisition.
    assert_eq!(interrupted.replay(), 1);
    assert!(!interrupted.own_report.exists());
    interrupted.preserved();
}
fn qualify_changed_path(session: &Path) {
    let changed = Fixture::create(session, "path-change");
    changed.arm();
    let hidden_image = changed.image.with_extension("unavailable");
    std::fs::rename(&changed.image, &hidden_image).unwrap();
    assert_eq!(changed.replay(), 0);
    changed.pending();
    std::fs::rename(&hidden_image, &changed.image).unwrap();
    let moved = session.join("path-change/moved-portable");
    std::fs::rename(&changed.root, &moved).unwrap();
    {
        let _install = crate::install::InstanceLock::acquire(&moved.join("Browser")).unwrap();
        assert_eq!(
            replay_with(
                &moved,
                "helium",
                &NativeBinding,
                |_| panic!("Moved original scope must not reach process query"),
                |_| panic!("Moved original scope must not clean")
            )
            .unwrap(),
            0
        );
        assert_eq!(records(&moved).unwrap().len(), 1);
    }
    std::fs::rename(&moved, &changed.root).unwrap();
    assert_eq!(changed.replay(), 1);
    changed.preserved();
}
#[test]
#[ignore = "explicit second disposable context; refusal results require independent key-context interpretation"]
fn qualify_foreign_context() {
    let session = session();
    let source = Path::new(r"C:\NomadForeignInput");
    let nested =
        crate::version_cache::read_bounded(&source.join("native-protected.bin"), MAX_BYTES)
            .expect("bounded foreign nested blob");
    let machine =
        crate::version_cache::read_bounded(&source.join("machine-protected.bin"), MAX_BYTES)
            .expect("bounded foreign machine blob");
    let nested_refused = NativeBinding.open(&nested).is_err();
    let machine_refused = dpapi(&machine, false, false).is_err();
    let results = serde_json::json!({
        "schema": 1, "nested_blob_refused": nested_refused, "machine_blob_refused": machine_refused,
        "scope": "second disposable context observation; not an isolated different-user test or proof of independent machine keys"
    });
    crate::fs_safety::write_new(
        &session.join("foreign-results.json"),
        &serde_json::to_vec_pretty(&results).unwrap(),
    )
    .unwrap();
    assert!(nested_refused && machine_refused, "Context could decrypt exported data; investigate cloned/shared key stores before claiming separation");
    println!("FOREIGN CONTEXT REFUSED BOTH PUBLIC PAYLOAD BLOBS; independent key contexts still require qualification.");
}
#[test]
fn qualification_token_rejects_path_and_command_injection() {
    assert!(valid_token("0123456789abcdef0123456789abcdef"));
    for token in [
        "",
        "../fixture",
        r"C:\fixture",
        "0123456789ABCDEF0123456789ABCDEF",
        "$(whoami)",
        "0123456789abcdef0123456789abcdef/other",
    ] {
        assert!(!valid_token(token));
    }
}
