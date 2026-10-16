//! Ignored, explicitly enrolled VM-only binding checks. Never run in the normal gate.
//! No host trace scanner, process creation, registry write, or browser is used.
use super::*;
use sha2::{Digest, Sha256};

const INPUT: &str = r"C:\NomadVmRecoveryInput";
const ORIGIN_INPUT: &str = r"C:\NomadVmRecoveryOrigin";
const PAYLOAD: &[u8] = b"Public inert Nomad independent-VM binding payload v1";
const BLOBS: [&str; 4] = ["nested.bin", "user.bin", "machine.bin", "journal.bin"];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    schema: u8,
    campaign: String,
    environment: String,
    machine_role: String,
    independently_initialized: bool,
    no_personal_data: bool,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Context {
    machine: String,
    user: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Origin {
    schema: u8,
    campaign: String,
    context: Context,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferFile {
    name: String,
    bytes: u64,
    sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferIndex {
    schema: u8,
    campaign: String,
    harness_sha256: String,
    files: Vec<TransferFile>,
}
fn harness_hash() -> String {
    digest(&std::fs::read(std::env::current_exe().unwrap()).unwrap())
}
fn checked_import(campaign: &str) -> PathBuf {
    let source = Path::new(ORIGIN_INPUT);
    let bytes = read(&source.join("BUNDLE-INDEX.json"));
    assert_eq!(
        digest(&bytes).to_ascii_uppercase(),
        std::env::var("NOMAD_VM_RECOVERY_BUNDLE_SHA256").unwrap()
    );
    let index: TransferIndex = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(index.schema, 1);
    assert_eq!(index.campaign, campaign);
    assert_eq!(index.harness_sha256, harness_hash());
    let mut names: Vec<&str> = index.files.iter().map(|f| f.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "journal.bin",
            "machine.bin",
            "nested.bin",
            "origin.json",
            "user.bin"
        ]
    );
    for file in index.files {
        let data = read(&source.join(file.name));
        assert_eq!(data.len() as u64, file.bytes);
        assert_eq!(digest(&data), file.sha256);
    }
    source.to_path_buf()
}
fn token_valid(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
fn enrollment_valid(e: &Enrollment, phase: &str, user: &str) -> bool {
    e.schema == 1
        && token_valid(&e.campaign)
        && e.environment == "independently_initialized_disposable_windows_vm"
        && e.independently_initialized
        && e.no_personal_data
        && matches!(
            (phase, user, e.machine_role.as_str()),
            ("Origin" | "ReturnOrigin", "NomadRecoverySource", "origin")
                | ("PeerUser", "NomadRecoveryPeer", "origin")
                | ("ForeignMachine", "NomadRecoveryForeign", "foreign")
        )
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn context(campaign: &str) -> io::Result<Context> {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        Security::{GetLengthSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    let key = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE).open_subkey_with_flags(
        r"SOFTWARE\Microsoft\Cryptography",
        winreg::enums::KEY_READ | winreg::enums::KEY_WOW64_64KEY,
    )?;
    let guid: String = key.get_value("MachineGuid")?;
    if guid.is_empty() || guid.len() > 128 {
        return Err(io::Error::other("invalid public machine identifier"));
    }
    let mut handle = std::ptr::null_mut();
    // SAFETY: borrowed pseudo-handle and initialized owned token-handle output.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let mut size = 0;
        // SAFETY: size query; no output buffer is supplied.
        unsafe { GetTokenInformation(handle, TokenUser, std::ptr::null_mut(), 0, &raw mut size) };
        if size == 0 || size > 65_536 {
            return Err(io::Error::other("token identity size refused"));
        }
        let mut words = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: naturally aligned buffer has at least the requested capacity.
        if unsafe {
            GetTokenInformation(
                handle,
                TokenUser,
                words.as_mut_ptr().cast(),
                size,
                &raw mut size,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful TokenUser query initialized this aligned structure.
        let token = unsafe { &*words.as_ptr().cast::<TOKEN_USER>() };
        // SAFETY: SID pointer belongs to the retained successful token query buffer.
        let length = unsafe { GetLengthSid(token.User.Sid) };
        if length == 0 || length > 1024 {
            return Err(io::Error::other("token SID size refused"));
        }
        // SAFETY: the valid SID remains inside the live token buffer.
        let sid =
            unsafe { std::slice::from_raw_parts(token.User.Sid.cast::<u8>(), length as usize) };
        Ok(Context {
            machine: digest(
                format!("nomad-vm:{campaign}:machine:{}", guid.to_ascii_lowercase()).as_bytes(),
            ),
            user: digest(&[format!("nomad-vm:{campaign}:user:").as_bytes(), sid].concat()),
        })
    })();
    // SAFETY: this owned handle was returned by OpenProcessToken above.
    unsafe { CloseHandle(handle) };
    result
}
fn read(path: &Path) -> Vec<u8> {
    crate::version_cache::read_bounded(path, MAX_BYTES).expect("ordinary bounded public fixture")
}
fn session() -> (Enrollment, String, PathBuf, Context) {
    let phase = std::env::var("NOMAD_VM_RECOVERY_PHASE").expect("explicit VM runner required");
    let user = std::env::var("USERNAME").unwrap();
    assert_ne!(
        user, "WDAGUtilityAccount",
        "Sandbox is not an independent Windows VM"
    );
    assert_eq!(
        std::env::var("USERDOMAIN").unwrap(),
        std::env::var("COMPUTERNAME").unwrap(),
        "fresh local VM account only"
    );
    let profile = PathBuf::from(format!(r"C:\Users\{user}"));
    assert_eq!(
        PathBuf::from(std::env::var("USERPROFILE").unwrap()),
        profile
    );
    let exe = std::env::current_exe().unwrap();
    crate::fs_safety::ensure_file(&exe).unwrap();
    assert_eq!(
        exe.parent(),
        Some(Path::new(INPUT)),
        "fixed read-only VM input only"
    );
    let enrollment: Enrollment =
        serde_json::from_slice(&read(&Path::new(INPUT).join("DISPOSABLE-VM.json"))).unwrap();
    assert!(
        enrollment_valid(&enrollment, &phase, &user),
        "explicit disposable VM enrollment refused"
    );
    let root = profile
        .join("AppData/Local/NomadVmRecoveryQualification")
        .join(&enrollment.campaign)
        .join(&phase);
    crate::fs_safety::ensure_directory(&root).unwrap();
    assert_eq!(
        std::fs::read_to_string(root.join("OWNER.txt")).unwrap(),
        format!(
            "Nomad independent VM binding fixture v1\n{}\n{phase}\n",
            enrollment.campaign
        )
    );
    let actual = context(&enrollment.campaign).unwrap();
    (enrollment, phase, root, actual)
}
fn portable(root: &Path) -> PathBuf {
    let instance = root.join("portable");
    let image = instance.join("Browser/inert.exe");
    crate::fs_safety::create_dir_all(image.parent().unwrap()).unwrap();
    crate::fs_safety::write_new(&image, b"INERT public marker, never executed").unwrap();
    crate::instance::ensure(&instance, "helium", true).unwrap();
    instance
}
fn public_roundtrip(result: io::Result<Vec<u8>>) -> bool {
    result.is_ok_and(|v| v == PAYLOAD)
}
fn qualify_origin(
    enrollment: &Enrollment,
    root: &Path,
    actual: &Context,
    result: &mut serde_json::Value,
) -> bool {
    let nested = NativeBinding.seal(PAYLOAD).unwrap();
    let user = dpapi(PAYLOAD, true, false).unwrap();
    let machine = dpapi(PAYLOAD, true, true).unwrap();
    let roundtrip = public_roundtrip(NativeBinding.open(&nested))
        && public_roundtrip(dpapi(&user, false, false))
        && public_roundtrip(dpapi(&machine, false, false));
    let instance = portable(root);
    let _lock = crate::install::InstanceLock::acquire(&instance.join("Browser")).unwrap();
    arm_with(
        &instance,
        &instance.join("Browser/inert.exe"),
        "helium",
        &NativeBinding,
    )
    .unwrap();
    let paths = records(&instance).unwrap();
    assert_eq!(paths.len(), 1);
    let journal = read(&paths[0]);
    let source = root.join("Transfer");
    crate::fs_safety::create_dir_all(&source).unwrap();
    for (name, bytes) in [
        ("nested.bin", nested),
        ("user.bin", user),
        ("machine.bin", machine),
        ("journal.bin", journal),
    ] {
        crate::fs_safety::write_new(&source.join(name), &bytes).unwrap();
    }
    crate::fs_safety::write_new(
        &source.join("origin.json"),
        &serde_json::to_vec(&Origin {
            schema: 1,
            campaign: enrollment.campaign.clone(),
            context: actual.clone(),
        })
        .unwrap(),
    )
    .unwrap();
    let files = [
        "journal.bin",
        "machine.bin",
        "nested.bin",
        "origin.json",
        "user.bin",
    ]
    .map(|name| {
        let bytes = read(&source.join(name));
        TransferFile {
            name: name.into(),
            bytes: bytes.len() as u64,
            sha256: digest(&bytes),
        }
    })
    .into();
    let index = TransferIndex {
        schema: 1,
        campaign: enrollment.campaign.clone(),
        harness_sha256: harness_hash(),
        files,
    };
    crate::fs_safety::write_new(
        &source.join("BUNDLE-INDEX.json"),
        &serde_json::to_vec_pretty(&index).unwrap(),
    )
    .unwrap();
    result["roundtrip"] = roundtrip.into();
    result["intent_retained"] = (paths[0].is_file()).into();
    roundtrip
}
fn replay_phase(
    enrollment: &Enrollment,
    phase: &str,
    root: &Path,
    journal: &[u8],
) -> (usize, usize, bool) {
    if phase == "ReturnOrigin" {
        let instance = root.parent().unwrap().join("Origin/portable");
        crate::fs_safety::ensure_directory(&instance).unwrap();
        assert_eq!(
            std::fs::read_to_string(instance.parent().unwrap().join("OWNER.txt")).unwrap(),
            format!(
                "Nomad independent VM binding fixture v1\n{}\nOrigin\n",
                enrollment.campaign
            )
        );
        let paths = records(&instance).unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(read(&paths[0]), journal);
        let _lock = crate::install::InstanceLock::acquire(&instance.join("Browser")).unwrap();
        let retired = replay_with(
            &instance,
            "helium",
            &NativeBinding,
            |_| Presence::Idle,
            |_| true,
        )
        .unwrap();
        (retired, records(&instance).unwrap().len(), true)
    } else {
        let instance = portable(root);
        let dir = directory(&instance);
        crate::fs_safety::create_dir_all(&dir).unwrap();
        let path = dir.join("pending-0123456789abcdef.bin");
        crate::fs_safety::write_new(&path, journal).unwrap();
        let _lock = crate::install::InstanceLock::acquire(&instance.join("Browser")).unwrap();
        let retired = replay_with(
            &instance,
            "helium",
            &NativeBinding,
            |_| panic!("foreign encrypted fixture must not reach process query"),
            |_| panic!("foreign encrypted fixture must not reach cleanup"),
        )
        .unwrap();
        (
            retired,
            records(&instance).unwrap().len(),
            read(&path) == journal,
        )
    }
}
fn qualify_import(
    enrollment: &Enrollment,
    phase: &str,
    root: &Path,
    actual: &Context,
    result: &mut serde_json::Value,
) -> bool {
    let source = checked_import(&enrollment.campaign);
    let origin: Origin = serde_json::from_slice(&read(&source.join("origin.json"))).unwrap();
    assert_eq!(origin.schema, 1);
    assert_eq!(origin.campaign, enrollment.campaign);
    let blobs: Vec<Vec<u8>> = BLOBS.iter().map(|name| read(&source.join(name))).collect();
    let nested_result = NativeBinding.open(&blobs[0]);
    let nested_refused = nested_result.is_err();
    let nested_ok = public_roundtrip(nested_result);
    let user_result = dpapi(&blobs[1], false, false);
    let user_refused = user_result.is_err();
    let user_ok = public_roundtrip(user_result);
    let machine_result = dpapi(&blobs[2], false, false);
    let machine_refused = machine_result.is_err();
    let machine_ok = public_roundtrip(machine_result);
    let journal_refused = NativeBinding
        .open(blobs[3].strip_prefix(MAGIC).expect("journal prefix"))
        .is_err();
    let (same_machine, same_user) = (
        actual.machine == origin.context.machine,
        actual.user == origin.context.user,
    );
    let (retired, retained, bytes_retained) = replay_phase(enrollment, phase, root, &blobs[3]);
    let qualified = if phase == "ReturnOrigin" {
        same_machine
            && same_user
            && nested_ok
            && user_ok
            && machine_ok
            && retired == 1
            && retained == 0
    } else {
        result["intent_bytes_unchanged"] = bytes_retained.into();
        !same_user
            && nested_refused
            && user_refused
            && journal_refused
            && retired == 0
            && retained == 1
            && bytes_retained
            && if phase == "PeerUser" {
                same_machine && machine_ok
            } else {
                !same_machine && machine_refused
            }
    };
    result["origin_context"] = serde_json::to_value(origin.context).unwrap();
    result["same_machine"] = same_machine.into();
    result["same_user"] = same_user.into();
    result["nested_payload_refused"] = nested_refused.into();
    result["user_payload_refused"] = user_refused.into();
    result["machine_payload_refused"] = machine_refused.into();
    result["nested_payload_opened"] = nested_ok.into();
    result["user_payload_opened"] = user_ok.into();
    result["machine_payload_opened"] = machine_ok.into();
    result["journal_ciphertext_refused"] = journal_refused.into();
    result["retired"] = retired.into();
    result["retained"] = retained.into();
    qualified
}
#[test]
#[ignore = "explicit enrolled independent disposable VMs only; never select in the host gate"]
fn qualify_enrolled_vm_binding() {
    let (enrollment, phase, root, actual) = session();
    let mut result = serde_json::json!({
        "schema": 1, "campaign": enrollment.campaign, "phase": phase,
        "context": actual, "scope": "public payload and inert journal only; no host trace scanner invoked"
    });
    let qualified = if phase == "Origin" {
        qualify_origin(&enrollment, &root, &actual, &mut result)
    } else {
        qualify_import(&enrollment, &phase, &root, &actual, &mut result)
    };
    result["qualified"] = qualified.into();
    crate::fs_safety::write_new(
        &root.join("RESULT.json"),
        &serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    assert!(qualified, "VM binding matrix did not qualify; retain all evidence and investigate context/key cloning");
    println!("ENROLLED VM BINDING PHASE PASSED; public inert fixtures only; independent host verification required.");
}

#[test]
fn enrollment_requires_declared_independence_and_exact_disposable_roles() {
    let mut e = Enrollment {
        schema: 1,
        campaign: "a".repeat(32),
        environment: "independently_initialized_disposable_windows_vm".into(),
        machine_role: "origin".into(),
        independently_initialized: true,
        no_personal_data: true,
    };
    assert!(enrollment_valid(&e, "Origin", "NomadRecoverySource"));
    assert!(enrollment_valid(&e, "PeerUser", "NomadRecoveryPeer"));
    for user in [
        "WDAGUtilityAccount",
        "PersonalUser",
        "Administrator",
        "NomadRecoveryForeign",
    ] {
        assert!(!enrollment_valid(&e, "Origin", user));
    }
    assert!(!enrollment_valid(
        &e,
        "ForeignMachine",
        "NomadRecoverySource"
    ));
    e.independently_initialized = false;
    assert!(!enrollment_valid(&e, "Origin", "NomadRecoverySource"));
    e.independently_initialized = true;
    e.no_personal_data = false;
    assert!(!enrollment_valid(&e, "Origin", "NomadRecoverySource"));
}
#[test]
fn campaign_and_enrollment_shapes_are_bounded_and_exact() {
    for value in [
        "",
        "../fixture",
        "a",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/other",
    ] {
        assert!(!token_valid(value));
    }
    assert!(token_valid("0123456789abcdef0123456789abcdef"));
    assert!(serde_json::from_str::<Enrollment>(r#"{"schema":1,"campaign":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","environment":"independently_initialized_disposable_windows_vm","machine_role":"origin","independently_initialized":true,"no_personal_data":true,"unexpected":1}"#).is_err());
}
