use std::fs;
use std::path::Path;
use std::process::Command;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_pki")
}

fn run(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(binary())
        .args(["--dir", dir.to_str().unwrap()])
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn list_empty_directory_succeeds() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(directory.path(), &["list"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("listed 0 certificate(s)"));
}

#[test]
fn list_reads_certificates_and_json_output() {
    let directory = tempfile::tempdir().unwrap();
    let certificate_directory = directory.path().join("certs");
    fs::create_dir_all(&certificate_directory).unwrap();
    let certificate = certificate_directory.join("example.pem");
    let generated = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout"])
        .arg(directory.path().join("key.pem"))
        .args(["-out"])
        .arg(&certificate)
        .args(["-subj", "/CN=example.test", "-days", "30"])
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );

    let output = run(directory.path(), &["--json", "list"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["certificates"][0]["common_name"], "example.test");
    assert_eq!(json["certificates"][0]["algorithm"], "Ed25519");
    assert!(
        json["certificates"][0]["expires"]
            .as_str()
            .unwrap()
            .contains("UTC")
    );
}

#[test]
fn verbose_list_includes_the_certificate_openssl_command() {
    let directory = tempfile::tempdir().unwrap();
    let certificate_directory = directory.path().join("certs");
    fs::create_dir_all(&certificate_directory).unwrap();
    let certificate = certificate_directory.join("example.pem");
    let generated = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout"])
        .arg(directory.path().join("key.pem"))
        .args(["-out"])
        .arg(&certificate)
        .args(["-subj", "/CN=example.test", "-days", "30"])
        .output()
        .unwrap();
    assert!(generated.status.success());

    let output = run(directory.path(), &["--verbose", "list"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("x509"));
    assert!(text.contains("-noout"));
    assert!(text.contains("-subject"));
    assert!(text.contains("-pubkey"));
    assert!(text.contains("stdout:"));
    assert!(text.contains("stderr:"));
    let summary = text.find("ok: listed").unwrap();
    let command = text.find("x509").unwrap();
    assert!(command < summary);
    assert!(!text[summary..].contains("openssl:"));
}

#[test]
fn human_list_indents_intermediates_and_leaves() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("ed25519/root/root/ca/certs");
    let intermediate = directory
        .path()
        .join("ed25519/intermediate/issuing/ca/certs");
    let leaf = directory.path().join("ed25519/certs/service/certs");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&intermediate).unwrap();
    fs::create_dir_all(&leaf).unwrap();
    let key = directory.path().join("key.pem");
    let root_cert = root.join("ca.cert.pem");
    let root_result = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout"])
        .arg(&key)
        .args(["-out"])
        .arg(&root_cert)
        .args(["-subj", "/CN=Root/O=Example", "-days", "30"])
        .output()
        .unwrap();
    assert!(root_result.status.success());
    let output = run(directory.path(), &["list"]);
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("root (root_ca)"));
}

#[test]
fn list_json_output_is_explicit_and_includes_name_fields() {
    let directory = tempfile::tempdir().unwrap();
    let certificate_directory = directory.path().join("ed25519/certs/service/certs");
    fs::create_dir_all(&certificate_directory).unwrap();
    let certificate = certificate_directory.join("cert.pem");
    let generated = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout"])
        .arg(directory.path().join("key.pem"))
        .args(["-out"])
        .arg(&certificate)
        .args(["-subj", "/CN=service.example", "-days", "30"])
        .output()
        .unwrap();
    assert!(generated.status.success());
    let output = run(directory.path(), &["--output", "json", "list"]);
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["certificates"][0]["name"], "service");
    assert_eq!(json["certificates"][0]["kind"], "certificate");
    assert_eq!(json["certificates"][0]["profile"], "ed25519");
}

#[test]
fn check_succeeds() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(directory.path(), &["check"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cert_dry_run_shows_planned_commands() {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("ecdsa-p256/root/ca");
    fs::create_dir_all(parent.join("certs")).unwrap();
    fs::create_dir_all(parent.join("private")).unwrap();
    fs::write(parent.join("private/ca.passphrase"), "root-secret\n").unwrap();
    fs::write(parent.join("private/ca.key.pem"), "placeholder-key").unwrap();
    let generated = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
        ])
        .arg(directory.path().join("root.key"))
        .args(["-out"])
        .arg(parent.join("certs/ca.cert.pem"))
        .args(["-subj", "/CN=Parent Root/O=Example", "-days", "30"])
        .output()
        .unwrap();
    assert!(generated.status.success());
    let output = run(
        directory.path(),
        &[
            "create-cert",
            "--cn",
            "Leaf",
            "--issuer",
            "root",
            "--san",
            "www.example.com",
            "--name",
            "leaf",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("planned certificate artifacts:"));
    assert!(text.contains("ecparam"));
    assert!(text.contains("req"));
    assert!(text.contains("-new"));
    assert!(text.contains("x509"));
    assert!(text.contains("-req"));
    assert!(text.contains("-days"));
    assert!(text.contains("30"));
    assert!(text.contains("\\"));
    assert!(!directory.path().join("ecdsa-p256/certs/leaf").exists());
}

#[test]
fn cert_help_requires_issuer_and_describes_inheritance() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(directory.path(), &["create-cert", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--issuer"));
    assert!(!help.contains("--root"));
    assert!(help.contains("inherit the issuer profile"));
    assert!(help.contains("secure random passphrase"));
}

#[test]
fn create_ca_help_describes_required_fields_and_duration_defaults() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(directory.path(), &["create-ca", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--name"));
    assert!(help.contains("--organization <ORGANIZATION>"));
    assert!(help.contains("--organizational-unit <ORGANIZATIONAL_UNIT>"));
    assert!(help.contains("--country <COUNTRY>"));
    assert!(help.contains("--state <STATE>"));
    assert!(help.contains("--locality <LOCALITY>"));
    assert!(help.contains("--profile <PROFILE>"));
    assert!(help.contains("Root profile is required"));
    assert!(help.contains("Root lifetime defaults to 5y"));
    assert!(help.contains("--days <DAYS>"));
    assert!(help.contains("Required certificate common name"));
}

#[test]
fn root_requires_all_subject_fields_and_profile() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(
        directory.path(),
        &[
            "create-ca",
            "--name",
            "root",
            "--common-name",
            "Example Root",
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.is_empty());
}

#[test]
fn root_accepts_all_required_subject_fields_and_profile() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(
        directory.path(),
        &[
            "create-ca",
            "--name",
            "root",
            "--common-name",
            "Example Root",
            "--organization",
            "Example Org",
            "--organizational-unit",
            "PKI",
            "--country",
            "US",
            "--state",
            "California",
            "--locality",
            "San Francisco",
            "--profile",
            "ed25519",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn duplicate_root_names_across_profiles_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let common = [
        "create-ca",
        "--name",
        "shared",
        "--common-name",
        "Example Root",
        "--organization",
        "Example",
        "--organizational-unit",
        "PKI",
        "--country",
        "US",
        "--state",
        "California",
        "--locality",
        "San Francisco",
        "--profile",
        "ecdsa-p256",
    ];
    let mut first_args = common.to_vec();
    first_args.extend(["--do-it"]);
    let first = run(directory.path(), &first_args);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let mut second_args = common.to_vec();
    let profile_index = second_args.len() - 1;
    second_args[profile_index] = "ed25519";
    second_args.extend(["--do-it"]);
    let second = run(directory.path(), &second_args);
    assert_eq!(second.status.code(), Some(5));
    assert!(String::from_utf8_lossy(&second.stderr).contains("CA name is already in use"));
}

#[test]
fn named_roots_can_share_a_profile_in_dry_run() {
    let directory = tempfile::tempdir().unwrap();
    let common = [
        "create-ca",
        "--common-name",
        "Example Root",
        "--organization",
        "Example",
        "--organizational-unit",
        "PKI",
        "--country",
        "US",
        "--state",
        "California",
        "--locality",
        "San Francisco",
        "--profile",
        "ed25519",
    ];
    let mut first = common.to_vec();
    first.extend(["--name", "first"]);
    let mut second = common.to_vec();
    second.extend(["--name", "second"]);

    let first_output = run(directory.path(), &first);
    let second_output = run(directory.path(), &second);
    assert!(first_output.status.success());
    assert!(second_output.status.success());
    assert!(String::from_utf8_lossy(&first_output.stdout).contains("ed25519/root/first/ca"));
    assert!(String::from_utf8_lossy(&second_output.stdout).contains("ed25519/root/second/ca"));
}

#[test]
fn duration_units_are_accepted_for_root_dry_runs() {
    let directory = tempfile::tempdir().unwrap();
    for (name, duration) in [
        ("days", "5d"),
        ("weeks", "5w"),
        ("months", "5m"),
        ("years", "5y"),
    ] {
        let output = run(
            directory.path(),
            &[
                "create-ca",
                "--name",
                name,
                "--common-name",
                "Example Root",
                "--organization",
                "Example",
                "--organizational-unit",
                "PKI",
                "--country",
                "US",
                "--state",
                "California",
                "--locality",
                "San Francisco",
                "--profile",
                "ecdsa-p256",
                "--days",
                duration,
            ],
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn create_ca_help_describes_parent_passphrase_option() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(directory.path(), &["create-ca", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--pathlen <PATHLEN>"));
    assert!(help.contains("--passphrase-file <PASSPHRASE_FILE>"));
    assert!(help.contains("--parent-passphrase-file <PARENT_PASSPHRASE_FILE>"));
    assert!(!help.contains("--issuer-passphrase-file"));
}

#[test]
fn create_ca_help_allows_inherited_subject_fields() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(directory.path(), &["create-ca", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("inherit from the parent"));
}

#[test]
fn intermediate_profile_can_be_omitted() {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir_all(directory.path().join("ed25519/root/ca/certs")).unwrap();
    let generated = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout"])
        .arg(directory.path().join("root.key"))
        .args(["-out"])
        .arg(directory.path().join("ed25519/root/ca/certs/ca.cert.pem"))
        .args([
            "-subj",
            "/CN=Parent Root/O=Example/OU=Parent CA/C=US/ST=NY/L=Albany",
            "-days",
            "30",
        ])
        .output()
        .unwrap();
    assert!(generated.status.success());
    let output = run(
        directory.path(),
        &[
            "create-ca",
            "--name",
            "issuing",
            "--parent",
            "root",
            "--common-name",
            "Issuing CA",
            "--organization",
            "Example",
            "--parent-passphrase-file",
            "missing.pass",
        ],
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("ed25519/intermediate/issuing"));
}

#[test]
fn intermediate_dry_run_shows_planned_commands_without_creating_files() {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("ecdsa-p256/root/ca");
    fs::create_dir_all(parent.join("certs")).unwrap();
    fs::create_dir_all(parent.join("private")).unwrap();
    fs::write(parent.join("private/ca.passphrase"), "root-secret\n").unwrap();
    let generated = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
        ])
        .arg(directory.path().join("root.key"))
        .args(["-out"])
        .arg(parent.join("certs/ca.cert.pem"))
        .args(["-subj", "/CN=Parent Root/O=Example", "-days", "30"])
        .output()
        .unwrap();
    assert!(generated.status.success());
    let output = run(
        directory.path(),
        &[
            "create-ca",
            "--name",
            "issuing",
            "--parent",
            "root",
            "--common-name",
            "Issuing CA",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("planned CA artifacts:"));
    assert!(text.contains("ecparam"));
    assert!(text.contains("req"));
    assert!(text.contains("-new"));
    assert!(text.contains("x509"));
    assert!(text.contains("-req"));
    assert!(text.contains("-days"));
    assert!(text.contains("730"));
    assert!(text.contains("\\"));
    assert!(text.contains("csr/ca.csr.pem"));
    assert!(!parent.join("../.pki-intermediate-ext").exists());
    assert!(
        !directory
            .path()
            .join("ecdsa-p256/intermediate/issuing/ca")
            .exists()
    );
}

#[test]
fn root_dry_run_shows_planned_creation_without_creating_files() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(
        directory.path(),
        &[
            "create-ca",
            "--name",
            "preview",
            "--profile",
            "ecdsa-p256",
            "--common-name",
            "Example Root",
            "--organization",
            "Example",
            "--organizational-unit",
            "PKI",
            "--country",
            "US",
            "--state",
            "California",
            "--locality",
            "San Francisco",
            "--days",
            "5y",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("dry-run: root CA would be created for 1825 days"));
    assert!(text.contains("planned root CA artifacts:"));
    assert!(text.contains("planned OpenSSL commands:"));
    assert!(text.contains("ecparam"));
    assert!(text.contains("req"));
    assert!(text.contains("-x509"));
    assert!(text.contains("-days"));
    assert!(text.contains("1825"));
    assert!(!directory.path().join("ecdsa-p256/root/preview/ca").exists());
}

#[test]
fn root_json_dry_run_contains_plans_without_secrets() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(
        directory.path(),
        &[
            "--json",
            "create-ca",
            "--name",
            "json-preview",
            "--common-name",
            "Example Root",
            "--organization",
            "Example",
            "--organizational-unit",
            "PKI",
            "--country",
            "US",
            "--state",
            "California",
            "--locality",
            "San Francisco",
            "--profile",
            "ecdsa-p256",
        ],
    );
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["dry_run"], true);
    assert!(json["planned_commands"].as_array().unwrap().len() >= 2);
    assert!(!json["planned_artifacts"].as_array().unwrap().is_empty());
    assert!(
        json.to_string()
            .contains("file:<generated-or-supplied-passphrase>")
            || json.to_string().contains("ecparam")
    );
    assert!(!json.to_string().contains("json-preview-generated"));
}

#[test]
fn removed_ca_commands_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    for command in ["create-root-ca", "create-intermediate-ca"] {
        let output = run(directory.path(), &[command]);
        assert!(!output.status.success(), "{command} should be rejected");
        assert!(String::from_utf8_lossy(&output.stderr).contains("error"));
    }
}

#[test]
fn create_ca_rejects_issuer_passphrase_option() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(
        directory.path(),
        &[
            "create-ca",
            "--name",
            "issuing",
            "--parent",
            "root",
            "--common-name",
            "Issuing CA",
            "--issuer-passphrase-file",
            "missing.pass",
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument"));
}

#[test]
fn verbose_create_ca_dry_run_reports_artifact_details() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(
        directory.path(),
        &[
            "--verbose",
            "create-ca",
            "--name",
            "root",
            "--profile",
            "ed25519",
            "--common-name",
            "Example Root",
            "--organization",
            "Example",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("planned artifacts:"));
    assert!(text.contains("created by: OpenSSL"));
    assert!(text.contains("$ openssl genpkey"));
    assert!(text.contains("-algorithm ED25519"));
    assert!(
        text.contains("generation: write the initial serial value 1000 followed by a newline")
            || text.contains("contents: 1000")
    );
    assert!(text.contains("contents: hidden; sensitive file"));
    assert!(text.contains("64 lowercase hexadecimal characters"));
    assert!(
        text.contains("empty file, 0 bytes")
            || text.contains("contents: empty file")
            || text.contains("contents: empty file, 0 bytes")
    );
    assert!(
        text.contains("root signing uses inline -addext arguments")
            || text.contains("contents: generated extension configuration")
    );
    assert!(!directory.path().join("ed25519/root/root/ca").exists());
}

#[test]
fn verbose_create_ca_execution_reports_public_and_sensitive_files() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(
        directory.path(),
        &[
            "--verbose",
            "create-ca",
            "--name",
            "root",
            "--profile",
            "ed25519",
            "--common-name",
            "Example Root",
            "--organization",
            "Example",
            "--organizational-unit",
            "PKI",
            "--country",
            "US",
            "--state",
            "NY",
            "--locality",
            "NYC",
            "--do-it",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("created files:"));
    assert!(text.contains("certs/ca.cert.pem"));
    assert!(text.contains("created by: OpenSSL"));
    assert!(text.contains("purpose: public certificate"));
    assert!(text.contains("created by: pki application"));
    assert!(text.contains("purpose: passphrase used to protect or unlock a private key"));
    assert!(text.contains("contents: hidden; sensitive file"));
    assert!(text.contains("64 lowercase hexadecimal characters"));
    assert!(!text.contains("BEGIN PRIVATE KEY"));
    assert!(!text.contains("BEGIN ENCRYPTED PRIVATE KEY"));
}

#[test]
fn verbose_create_cert_execution_reports_public_and_sensitive_files() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("ed25519/root/ca");
    fs::create_dir_all(root.join("certs")).unwrap();
    fs::create_dir_all(root.join("private")).unwrap();
    fs::write(root.join("private/ca.passphrase"), "root-secret\n").unwrap();
    let generated_key = root.join("private/ca.key.pem");
    let generated = Command::new("openssl")
        .args(["genpkey", "-algorithm", "ED25519", "-out"])
        .arg(&generated_key)
        .output()
        .unwrap();
    assert!(generated.status.success());
    let generated = Command::new("openssl")
        .args(["req", "-x509", "-new", "-key"])
        .arg(&generated_key)
        .args(["-out"])
        .arg(root.join("certs/ca.cert.pem"))
        .args(["-subj", "/CN=Parent Root/O=Example", "-days", "30"])
        .output()
        .unwrap();
    assert!(generated.status.success());
    let output = run(
        directory.path(),
        &[
            "--verbose",
            "create-cert",
            "--cn",
            "Leaf",
            "--issuer",
            "root",
            "--san",
            "www.example.com",
            "--name",
            "leaf",
            "--do-it",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("created files:"));
    assert!(text.contains("certs/cert.pem"));
    assert!(text.contains("created by: OpenSSL"));
    assert!(text.contains("purpose: public certificate"));
    assert!(text.contains("created by: pki application"));
    assert!(text.contains("purpose: passphrase used to protect or unlock a private key"));
    assert!(text.contains("contents: hidden; sensitive file"));
    assert!(text.contains("64 lowercase hexadecimal characters"));
    assert!(!text.contains("BEGIN PRIVATE KEY"));
    assert!(!text.contains("BEGIN ENCRYPTED PRIVATE KEY"));
}

#[test]
fn create_ca_root_rejects_parent_passphrase_before_open_ssl() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(
        directory.path(),
        &[
            "create-ca",
            "--name",
            "root",
            "--profile",
            "ed25519",
            "--common-name",
            "Example Root",
            "--organization",
            "Example",
            "--parent-passphrase-file",
            "missing.pass",
            "--do-it",
        ],
    );
    assert_eq!(output.status.code(), Some(4));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--parent-passphrase-file is only valid with --parent")
    );
    assert!(!directory.path().join("ed25519/root/root/ca").exists());
}
