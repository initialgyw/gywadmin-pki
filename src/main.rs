use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use time::OffsetDateTime;
use x509_parser::extensions::GeneralName;
use x509_parser::pem::parse_x509_pem;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Report {
    schema_version: u8,
    ok: bool,
    code: u8,
    error: Option<String>,
    message: String,
    dry_run: bool,
    paths: Vec<String>,
    commands: Vec<CommandReport>,
    planned_commands: Vec<Vec<String>>,
    planned_artifacts: Vec<String>,
    certificates: Option<Vec<CertificateRecord>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommandReport {
    argv: Vec<String>,
    success: bool,
    code: Option<i32>,
    stdout: String,
    stderr: String,
    stdout_bytes: usize,
    stderr_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CertificateRecord {
    path: String,
    name: Option<String>,
    kind: String,
    profile: Option<String>,
    common_name: String,
    algorithm: String,
    expires: String,
    issuer: String,
    subject: String,
    domains: Vec<String>,
}

#[derive(Debug, Clone, ValueEnum)]
enum Profile {
    #[value(name = "ecdsa-p256")]
    EcdsaP256,
    Ed25519,
    #[value(name = "rsa-4096")]
    Rsa4096,
}

impl Profile {
    fn all() -> [Self; 3] {
        [Self::EcdsaP256, Self::Ed25519, Self::Rsa4096]
    }

    fn text(&self) -> &'static str {
        match self {
            Self::EcdsaP256 => "ecdsa-p256",
            Self::Ed25519 => "ed25519",
            Self::Rsa4096 => "rsa-4096",
        }
    }
}

#[derive(Debug, Clone, Args)]
struct SubjectArgs {
    #[arg(
        long = "common-name",
        visible_alias = "cn",
        help = "Required certificate common name."
    )]
    common_name: String,
    #[arg(
        short = 'o',
        long,
        help = "Organization name. For intermediate CAs, omitted means inherit from the parent."
    )]
    organization: Option<String>,
    #[arg(
        long,
        visible_alias = "ou",
        help = "Optional organizational unit; intermediate CAs inherit it when omitted."
    )]
    organizational_unit: Option<String>,
    #[arg(
        long,
        help = "Optional two-letter country code; intermediate CAs inherit it when omitted."
    )]
    country: Option<String>,
    #[arg(
        long,
        help = "Optional state or province; intermediate CAs inherit it when omitted."
    )]
    state: Option<String>,
    #[arg(
        long,
        help = "Optional locality; intermediate CAs inherit it when omitted."
    )]
    locality: Option<String>,
}

impl SubjectArgs {
    fn distinguished_name(&self) -> String {
        let mut fields = vec![
            format!("/CN={}", self.common_name),
            format!("/O={}", self.organization.as_deref().unwrap_or_default()),
        ];
        if let Some(value) = &self.organizational_unit {
            fields.push(format!("/OU={value}"));
        }
        if let Some(value) = &self.country {
            fields.push(format!("/C={value}"));
        }
        if let Some(value) = &self.state {
            fields.push(format!("/ST={value}"));
        }
        if let Some(value) = &self.locality {
            fields.push(format!("/L={value}"));
        }
        fields.join("")
    }
}

#[derive(Debug, Clone, Args)]
struct RootArgs {
    #[command(flatten)]
    subject: SubjectArgs,
    #[arg(long, help = "Required unique directory name for this root CA.")]
    name: String,
    #[arg(
        long,
        value_enum,
        default_value = "ecdsa-p256",
        help = "Optional key profile. Defaults to ecdsa-p256."
    )]
    profile: Profile,
    #[arg(
        long,
        default_value = "5y",
        help = "Optional lifetime: a number of days or a number ending in d, w, m, or y. Defaults to 5y; months are 30 days and years are 365 days."
    )]
    days: CertificateDuration,
    #[arg(
        long,
        default_value_t = 1,
        help = "Optional maximum subordinate CA depth. Defaults to 1."
    )]
    pathlen: u32,
    #[arg(
        long,
        help = "Optional existing passphrase file; otherwise one is generated during execution."
    )]
    passphrase_file: Option<PathBuf>,
    #[arg(
        long,
        help = "Execute the operation. Without this flag, only validation is performed."
    )]
    do_it: bool,
}

#[derive(Debug, Clone, Args)]
struct IntermediateArgs {
    #[command(flatten)]
    subject: SubjectArgs,
    #[arg(
        long,
        value_enum,
        help = "Optional key profile. If omitted, inherit the parent CA profile."
    )]
    profile: Option<Profile>,
    #[arg(long, help = "Required safe directory name for the intermediate CA.")]
    name: String,
    #[arg(
        long,
        help = "Required parent selector: root, root:<name>, or intermediate:<name>."
    )]
    parent: String,
    #[arg(
        long,
        default_value = "2y",
        help = "Optional lifetime: a number of days or a number ending in d, w, m, or y. Defaults to 2y; months are 30 days and years are 365 days."
    )]
    days: CertificateDuration,
    #[arg(
        long,
        default_value_t = 0,
        help = "Optional maximum subordinate CA depth. Defaults to 0."
    )]
    pathlen: u32,
    #[arg(
        long,
        help = "Optional existing passphrase file; otherwise one is generated during execution."
    )]
    passphrase_file: Option<PathBuf>,
    #[arg(
        long,
        help = "Optional parent passphrase file; defaults to the parent's private/ca.passphrase."
    )]
    issuer_passphrase_file: Option<PathBuf>,
    #[arg(
        long,
        help = "Execute the operation. Without this flag, only validation is performed."
    )]
    do_it: bool,
}

#[derive(Debug, Clone, Args)]
struct CertArgs {
    #[command(flatten)]
    subject: SubjectArgs,
    #[arg(
        long,
        value_enum,
        help = "Optional key profile. If omitted, inherit the issuer profile."
    )]
    profile: Option<Profile>,
    #[arg(
        long,
        help = "Required safe output directory name for the certificate."
    )]
    name: String,
    #[arg(
        long,
        help = "Required issuer selector: root, root:<name>, or intermediate:<name>."
    )]
    issuer: String,
    #[arg(
        long,
        default_value = "30d",
        help = "Optional lifetime: a number of days or a number ending in d, w, m, or y. Defaults to 30d; months are 30 days and years are 365 days."
    )]
    days: CertificateDuration,
    #[arg(
        long = "san",
        help = "Required DNS name or IP address; repeat for multiple SANs."
    )]
    san: Vec<String>,
    #[arg(long, hide = true)]
    dns: Vec<String>,
    #[arg(long, hide = true)]
    ip: Vec<String>,
    #[arg(
        long,
        help = "Optional leaf passphrase file; otherwise generate a secure random passphrase."
    )]
    passphrase_file: Option<PathBuf>,
    #[arg(
        long,
        help = "Optional issuer passphrase file; defaults to the issuer's private/ca.passphrase."
    )]
    issuer_passphrase_file: Option<PathBuf>,
    #[arg(
        long,
        help = "Execute the operation. Without this flag, only validation is performed."
    )]
    do_it: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum DurationUnit {
    Days,
    Weeks,
    Months,
    Years,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CertificateDuration {
    amount: u32,
    unit: DurationUnit,
}

impl FromStr for CertificateDuration {
    type Err = String;

    /// Parses a command-line lifetime into a number and a duration unit.
    ///
    /// Input shape: a borrowed string such as `"5y"` or `"1825"`.
    /// Output shape: an owned `CertificateDuration` containing the amount and unit.
    /// The owned result is returned because it must outlive this parser call.
    ///
    /// # Arguments
    ///
    /// * `value` - Text supplied after the `--days` option.
    ///
    /// # Returns
    ///
    /// A parsed duration, where a bare number means days.
    ///
    /// # Errors
    ///
    /// Returns a message when the amount is missing, zero, malformed, or has an unsupported unit.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (amount_text, unit) = match value.chars().last() {
            Some('d') => (&value[..value.len() - 1], DurationUnit::Days),
            Some('w') => (&value[..value.len() - 1], DurationUnit::Weeks),
            Some('m') => (&value[..value.len() - 1], DurationUnit::Months),
            Some('y') => (&value[..value.len() - 1], DurationUnit::Years),
            Some(character) if character.is_ascii_digit() => (value, DurationUnit::Days),
            Some(character) => {
                return Err(format!(
                    "invalid duration unit '{character}'; use d, w, m, or y"
                ));
            }
            None => return Err("duration cannot be empty".into()),
        };
        let amount = amount_text
            .parse::<u32>()
            .map_err(|_| format!("invalid duration amount: {amount_text}"))?;
        if amount == 0 {
            return Err("duration must be greater than zero".into());
        }
        Ok(Self { amount, unit })
    }
}

impl CertificateDuration {
    /// Converts this duration to the integer day count required by OpenSSL.
    ///
    /// Input shape: an amount and one enum unit.
    /// Output shape: one checked `u32` day count.
    /// Months use 30 days and years use 365 days because OpenSSL accepts days,
    /// not calendar-aware month or year values.
    ///
    /// # Arguments
    ///
    /// * `self` - The parsed duration being converted.
    ///
    /// # Returns
    ///
    /// The equivalent number of days.
    ///
    /// # Errors
    ///
    /// Returns an error if multiplication would overflow `u32`.
    fn to_days(&self) -> Result<u32, String> {
        let multiplier = match self.unit {
            DurationUnit::Days => 1,
            DurationUnit::Weeks => 7,
            DurationUnit::Months => 30,
            DurationUnit::Years => 365,
        };
        self.amount
            .checked_mul(multiplier)
            .ok_or_else(|| "duration is too large".to_owned())
    }
}

#[derive(Debug, Clone, Parser)]
#[command(name = "pki", version, about = "Offline OpenSSL PKI manager")]
struct Cli {
    #[arg(long)]
    dir: PathBuf,
    #[arg(short, long)]
    verbose: bool,
    #[arg(long, default_value = "openssl")]
    openssl_binary: PathBuf,
    #[arg(long, default_value = "human")]
    output: String,
    #[arg(long)]
    json: bool,
    #[command(subcommand)]
    command: Operation,
}

#[derive(Debug, Clone, Subcommand)]
enum Operation {
    Check,
    CreateRootCa(RootArgs),
    CreateIntermediateCa(IntermediateArgs),
    CreateCert(CertArgs),
    List,
}

#[derive(Debug, Clone)]
struct OpenSsl {
    binary: PathBuf,
    commands: Vec<CommandReport>,
}

impl OpenSsl {
    /// Runs one OpenSSL process and records stdout, stderr, and exit status.
    ///
    /// `&mut self` is a mutable borrow: the caller keeps ownership of the
    /// runner while this method appends one audit record.
    ///
    /// # Arguments
    ///
    /// * `args` - OpenSSL arguments, excluding the executable name.
    ///
    /// # Returns
    ///
    /// Captured stdout bytes when the process succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error when the executable cannot start or exits unsuccessfully.
    fn run(&mut self, args: &[String]) -> Result<Vec<u8>, String> {
        let output = Command::new(&self.binary)
            .args(args)
            .output()
            .map_err(|error| format!("cannot launch OpenSSL: {error}"))?;
        let report = CommandReport {
            argv: std::iter::once(self.binary.to_string_lossy().into_owned())
                .chain(args.iter().cloned())
                .collect(),
            success: output.status.success(),
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            stdout_bytes: output.stdout.len(),
            stderr_bytes: output.stderr.len(),
        };
        let error = report.stderr.trim().to_owned();
        self.commands.push(report);
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(format!("OpenSSL failed: {error}"))
        }
    }
}

fn main() {
    let cli = match Cli::try_parse() {
        Ok(value) => value,
        Err(error) => error.exit(),
    };
    let json = cli.json || cli.output == "json";
    let mut openssl = OpenSsl {
        binary: cli.openssl_binary.clone(),
        commands: Vec::new(),
    };
    let result = execute(&cli, &mut openssl);
    match result {
        Ok(mut report) => {
            report.commands = openssl.commands;
            if json {
                println!("{}", serde_json::to_string(&report).unwrap());
            } else if let Some(certificates) = report.certificates {
                if cli.verbose {
                    print_verbose_commands(&report.commands);
                }
                println!("ok: {}", report.message);
                println!("{}", render_tree(&certificates));
            } else {
                if cli.verbose {
                    print_verbose_commands(&report.commands);
                }
                print_planned_root(&report);
                println!("ok: {}", report.message);
                for path in report.paths {
                    println!("{path}");
                }
            }
        }
        Err((code, message)) => {
            let report = Report {
                schema_version: 1,
                ok: false,
                code,
                error: Some(message),
                message: "operation failed".into(),
                dry_run: true,
                paths: Vec::new(),
                commands: openssl.commands,
                planned_commands: Vec::new(),
                planned_artifacts: Vec::new(),
                certificates: None,
            };
            if json {
                eprintln!("{}", serde_json::to_string(&report).unwrap());
            } else {
                eprintln!("error: {}", report.error.unwrap_or_default());
            }
            std::process::exit(i32::from(code));
        }
    }
}

fn execute(cli: &Cli, openssl: &mut OpenSsl) -> Result<Report, (u8, String)> {
    if !cfg!(unix) {
        return Err((15, "pki is Unix-only".into()));
    }
    if !cli.dir.is_dir() {
        return Err((3, "--dir must be an existing directory".into()));
    }
    openssl
        .run(&["version".into()])
        .map_err(|error| (8, error))?;
    match &cli.command {
        Operation::Check => Ok(success("OpenSSL verified", true)),
        Operation::List => list_certificates(&cli.dir, openssl, cli.verbose),
        Operation::CreateRootCa(args) => create_root(&cli.dir, openssl, args),
        Operation::CreateIntermediateCa(args) => create_intermediate(&cli.dir, openssl, args),
        Operation::CreateCert(args) => create_certificate(&cli.dir, openssl, args),
    }
}

fn success(message: &str, dry_run: bool) -> Report {
    Report {
        schema_version: 1,
        ok: true,
        code: 0,
        error: None,
        message: message.into(),
        dry_run,
        paths: Vec::new(),
        commands: Vec::new(),
        planned_commands: Vec::new(),
        planned_artifacts: Vec::new(),
        certificates: None,
    }
}

fn create_root(dir: &Path, openssl: &mut OpenSsl, args: &RootArgs) -> Result<Report, (u8, String)> {
    validate_subject(&args.subject)?;
    let days = normalized_days(&args.days, 1, 7300)?;
    validate_name(&args.name)?;
    let target = dir
        .join(args.profile.text())
        .join("root")
        .join(&args.name)
        .join("ca");
    if target.exists() {
        return Err((5, format!("target already exists: {}", target.display())));
    }
    let relative = relative_path(dir, &target);
    let key = target.join("private/ca.key.pem");
    let cert = target.join("certs/ca.cert.pem");
    let ext = target.join("config/ca.ext");
    let planned_commands = root_command_plan(args, &key, &cert, days);
    let planned_artifacts = root_artifact_plan(dir, &target, args.passphrase_file.is_none());
    if !args.do_it {
        let mut report = success_with_path(
            &format!("dry-run: root CA would be created for {days} days"),
            true,
            relative,
        );
        report.planned_commands = planned_commands;
        report.planned_artifacts = planned_artifacts;
        return Ok(report);
    }
    fs::create_dir_all(target.join("private")).map_err(fs_error)?;
    fs::create_dir_all(target.join("certs")).map_err(fs_error)?;
    fs::create_dir_all(target.join("newcerts")).map_err(fs_error)?;
    fs::create_dir_all(target.join("config")).map_err(fs_error)?;
    let pass = passphrase(args.passphrase_file.as_deref(), dir, &target, openssl)?;
    generate_key(openssl, &args.profile, &key, &pass)?;
    write_new(&ext, &format!("basicConstraints=critical,CA:TRUE,pathlen:{}\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\n", args.pathlen)).map_err(fs_error)?;
    let mut root_certificate_args = vec![
        "req".into(),
        "-x509".into(),
        "-new".into(),
        "-key".into(),
        key.display().to_string(),
    ];
    if matches!(args.profile, Profile::Rsa4096) {
        root_certificate_args.extend([
            "-passin".into(),
            format!("file:{}", target.join("private/ca.passphrase").display()),
        ]);
    }
    root_certificate_args.extend([
        "-sha256".into(),
        "-days".into(),
        days.to_string(),
        "-subj".into(),
        args.subject.distinguished_name(),
        "-addext".into(),
        format!("basicConstraints=critical,CA:TRUE,pathlen:{}", args.pathlen),
        "-addext".into(),
        "keyUsage=critical,keyCertSign,cRLSign".into(),
        "-out".into(),
        cert.display().to_string(),
    ]);
    run_to_file(openssl, root_certificate_args)?;
    write_new(&target.join("index.txt"), "").map_err(fs_error)?;
    write_new(&target.join("serial"), "1000\n").map_err(fs_error)?;
    Ok(success_with_path("root CA created", false, relative))
}

fn create_intermediate(
    dir: &Path,
    openssl: &mut OpenSsl,
    args: &IntermediateArgs,
) -> Result<Report, (u8, String)> {
    validate_name(&args.name)?;
    let days = normalized_days(&args.days, 1, 3650)?;
    let parent = resolve_issuer(dir, &args.parent)?;
    let parent_subject = read_subject(&parent.path)?;
    let subject = inherited_subject(&parent_subject, &args.subject);
    validate_subject(&subject)?;
    let profile = match &args.profile {
        Some(profile) if profile.text() != parent.profile.text() => {
            return Err((
                4,
                format!(
                    "intermediate profile {} does not match parent profile {}",
                    profile.text(),
                    parent.profile.text()
                ),
            ));
        }
        Some(profile) => profile.clone(),
        None => parent.profile.clone(),
    };
    let target = dir
        .join(profile.text())
        .join("intermediate")
        .join(&args.name)
        .join("ca");
    if target.exists() {
        return Err((5, format!("target already exists: {}", target.display())));
    }
    let relative = relative_path(dir, &target);
    let key = target.join("private/ca.key.pem");
    let csr = target.join("csr/ca.csr.pem");
    let cert = target.join("certs/ca.cert.pem");
    let extension = intermediate_extension_path(dir, &args.name);
    let parent_key = parent
        .path
        .parent()
        .and_then(Path::parent)
        .map(|ca| ca.join("private/ca.key.pem"))
        .ok_or((6, "cannot determine parent key path".into()))?;
    let planned_commands = intermediate_command_plan(
        &profile,
        &key,
        &csr,
        &cert,
        &parent.path,
        &parent_key,
        &extension,
        &subject,
        days,
    );
    let planned_artifacts =
        intermediate_artifact_plan(dir, &target, &extension, args.passphrase_file.is_none());
    if !args.do_it {
        let mut report = success_with_path(
            &format!("dry-run: intermediate CA would be created for {days} days"),
            true,
            relative,
        );
        report.planned_commands = planned_commands;
        report.planned_artifacts = planned_artifacts;
        return Ok(report);
    }
    fs::create_dir_all(target.join("private")).map_err(fs_error)?;
    fs::create_dir_all(target.join("certs")).map_err(fs_error)?;
    fs::create_dir_all(target.join("csr")).map_err(fs_error)?;
    fs::create_dir_all(target.join("newcerts")).map_err(fs_error)?;
    fs::create_dir_all(target.join("config")).map_err(fs_error)?;
    fs::create_dir_all(target.join("chain")).map_err(fs_error)?;
    let pass = passphrase(args.passphrase_file.as_deref(), dir, &target, openssl)?;
    let issuer_passphrase_file = args
        .issuer_passphrase_file
        .as_deref()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| parent_default_passphrase(&parent.path));
    let issuer_pass = read_passphrase(dir, &issuer_passphrase_file).map_err(|(_, message)| {
        (
            4,
            format!(
                "cannot read parent passphrase file {}: {message}; provide --issuer-passphrase-file to override the default",
                issuer_passphrase_file.display()
            ),
        )
    })?;
    generate_key(openssl, &profile, &key, &pass)?;
    run_to_file(
        openssl,
        vec![
            "req".into(),
            "-new".into(),
            "-key".into(),
            key.display().to_string(),
            "-passin".into(),
            format!("pass:{pass}"),
            "-subj".into(),
            subject.distinguished_name(),
            "-out".into(),
            csr.display().to_string(),
        ],
    )?;
    run_to_file(
        openssl,
        vec![
            "x509".into(),
            "-req".into(),
            "-in".into(),
            csr.display().to_string(),
            "-CA".into(),
            parent.path.display().to_string(),
            "-CAkey".into(),
            parent
                .path
                .parent()
                .and_then(Path::parent)
                .map(|ca| ca.join("private/ca.key.pem"))
                .ok_or((6, "cannot determine parent key path".into()))?
                .display()
                .to_string(),
            "-passin".into(),
            format!("pass:{issuer_pass}"),
            "-days".into(),
            days.to_string(),
            "-set_serial".into(),
            "1000".into(),
            "-extfile".into(),
            write_extension(dir, &args.name, args.pathlen)?
                .display()
                .to_string(),
            "-out".into(),
            cert.display().to_string(),
        ],
    )?;
    write_new(&target.join("index.txt"), "").map_err(fs_error)?;
    write_new(&target.join("serial"), "1000\n").map_err(fs_error)?;
    let _ = write_chain(&target, &parent.path, &cert);
    Ok(success_with_path(
        "intermediate CA created",
        false,
        relative,
    ))
}

fn create_certificate(
    dir: &Path,
    openssl: &mut OpenSsl,
    args: &CertArgs,
) -> Result<Report, (u8, String)> {
    validate_name(&args.name)?;
    let days = normalized_days(&args.days, 1, 397)?;
    let sans = normalize_sans(args)?;
    let issuer = resolve_issuer(dir, &args.issuer)?;
    let parent_subject = read_subject(&issuer.path)?;
    let subject = inherited_subject(&parent_subject, &args.subject);
    validate_subject(&subject)?;
    let profile = match &args.profile {
        Some(profile) if profile.text() != issuer.profile.text() => {
            return Err((
                4,
                format!(
                    "certificate profile {} does not match issuer profile {}",
                    profile.text(),
                    issuer.profile.text()
                ),
            ));
        }
        Some(profile) => profile.clone(),
        None => issuer.profile.clone(),
    };
    let issuer_key = issuer
        .path
        .parent()
        .and_then(Path::parent)
        .map(|ca| ca.join("private/ca.key.pem"))
        .ok_or((6, "cannot determine issuer key path".into()))?;
    if !issuer_key.is_file() {
        return Err((
            4,
            format!(
                "issuer private key does not exist: {}",
                issuer_key.display()
            ),
        ));
    }
    let issuer_passphrase_file = args
        .issuer_passphrase_file
        .as_deref()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| parent_default_passphrase(&issuer.path));
    let issuer_pass = read_passphrase(dir, &issuer_passphrase_file).map_err(|(_, message)| {
        (
            4,
            format!(
                "cannot read issuer passphrase file {}: {message}",
                issuer_passphrase_file.display()
            ),
        )
    })?;
    if let Some(path) = &args.passphrase_file {
        read_passphrase(dir, path)?;
    }
    let target = dir.join(profile.text()).join("certs").join(&args.name);
    if target.exists() {
        return Err((5, format!("target already exists: {}", target.display())));
    }
    let relative = relative_path(dir, &target);
    let key = target.join("private/key.pem");
    let csr = target.join("csr/request.csr.pem");
    let cert = target.join("certs/cert.pem");
    let ext = target.join("config/leaf-ext.cnf");
    let planned_commands = certificate_command_plan(
        &profile,
        &key,
        &csr,
        &cert,
        &issuer.path,
        &issuer_key,
        &ext,
        &subject,
        days,
    );
    let planned_artifacts = certificate_artifact_plan(dir, &target, args.passphrase_file.is_none());
    if !args.do_it {
        let mut report = success_with_path(
            &format!("dry-run: certificate would be created for {days} days"),
            true,
            relative,
        );
        report.planned_commands = planned_commands;
        report.planned_artifacts = planned_artifacts;
        return Ok(report);
    }
    for child in ["private", "csr", "certs", "chain", "config"] {
        fs::create_dir_all(target.join(child)).map_err(|error| {
            (
                6,
                format!(
                    "cannot create leaf directory {}: {error}",
                    target.join(child).display()
                ),
            )
        })?;
    }
    let passphrase_file = args
        .passphrase_file
        .clone()
        .unwrap_or_else(|| target.join("private/passphrase"));
    let cleanup_target = target.clone();
    let pass = if args.passphrase_file.is_some() {
        read_passphrase(dir, &passphrase_file)?
    } else {
        let value = random_passphrase().map_err(|(_, message)| (6, message))?;
        write_new(&passphrase_file, &format!("{value}\n")).map_err(fs_error)?;
        value
    };
    let key = target.join("private/key.pem");
    let csr = target.join("csr/request.csr.pem");
    let cert = target.join("certs/cert.pem");
    if let Err((code, message)) = generate_key(openssl, &profile, &key, &pass) {
        let _ = fs::remove_dir_all(&cleanup_target);
        return Err((
            code,
            format!("cannot generate leaf key {}: {message}", key.display()),
        ));
    }
    run_to_file(
        openssl,
        vec![
            "req".into(),
            "-new".into(),
            "-key".into(),
            key.display().to_string(),
            "-passin".into(),
            format!("pass:{pass}"),
            "-subj".into(),
            subject.distinguished_name(),
            "-out".into(),
            csr.display().to_string(),
        ],
    )?;
    let ext = match write_leaf_extension(&target, &sans) {
        Ok(path) => path,
        Err(error) => {
            let _ = fs::remove_dir_all(&cleanup_target);
            return Err(error);
        }
    };
    let issuer_cert = issuer.path.clone();
    run_to_file(
        openssl,
        vec![
            "x509".into(),
            "-req".into(),
            "-in".into(),
            csr.display().to_string(),
            "-CA".into(),
            issuer_cert.display().to_string(),
            "-CAkey".into(),
            issuer_key.display().to_string(),
            "-passin".into(),
            format!("pass:{issuer_pass}"),
            "-days".into(),
            days.to_string(),
            "-set_serial".into(),
            "1001".into(),
            "-extfile".into(),
            ext.display().to_string(),
            "-out".into(),
            cert.display().to_string(),
        ],
    )?;
    write_chain(&target, &issuer_cert, &cert)
        .map_err(|error| (6, format!("cannot write certificate chain: {error}")))?;
    Ok(success_with_path("certificate created", false, relative))
}

fn generate_key(
    openssl: &mut OpenSsl,
    profile: &Profile,
    path: &Path,
    _pass: &str,
) -> Result<(), (u8, String)> {
    let args = if matches!(profile, Profile::Rsa4096) {
        let passphrase_file = path
            .parent()
            .ok_or((6, "cannot determine key directory".into()))?
            .join("passphrase");
        vec![
            "genrsa".into(),
            "-aes256".into(),
            "-passout".into(),
            format!("file:{}", passphrase_file.display()),
            "-out".into(),
            path.display().to_string(),
            "4096".into(),
        ]
    } else if matches!(profile, Profile::EcdsaP256) {
        vec![
            "ecparam".into(),
            "-name".into(),
            "prime256v1".into(),
            "-genkey".into(),
            "-noout".into(),
            "-out".into(),
            path.display().to_string(),
        ]
    } else {
        vec![
            "genpkey".into(),
            "-algorithm".into(),
            "ED25519".into(),
            "-out".into(),
            path.display().to_string(),
        ]
    };
    openssl.run(&args).map_err(|error| (10, error)).map(|_| ())
}

fn run_to_file(openssl: &mut OpenSsl, args: Vec<String>) -> Result<(), (u8, String)> {
    openssl.run(&args).map_err(|error| (10, error)).map(|_| ())
}

fn passphrase(
    input: Option<&Path>,
    dir: &Path,
    target: &Path,
    _openssl: &mut OpenSsl,
) -> Result<String, (u8, String)> {
    if let Some(path) = input {
        let value = read_passphrase(dir, path)?;
        write_new(&target.join("private/ca.passphrase"), &format!("{value}\n"))
            .map_err(fs_error)?;
        return Ok(value);
    }
    let value = random_passphrase()?;
    write_new(&target.join("private/ca.passphrase"), &format!("{value}\n")).map_err(fs_error)?;
    Ok(value)
}

/// Creates a cryptographically random 256-bit passphrase.
///
/// The input shape is no data: randomness comes from the operating system.
/// The output shape is a 64-character hexadecimal string, where every pair
/// of characters represents one random byte. Hexadecimal is used so the value
/// is safe to store as one line in a passphrase file.
///
/// # Arguments
///
/// This function has no arguments.
///
/// # Returns
///
/// A random passphrase string containing 32 random bytes encoded as hexadecimal.
///
/// # Errors
///
/// Returns an error when the operating system cannot provide secure randomness.
fn random_passphrase() -> Result<String, (u8, String)> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| (6, format!("cannot generate secure passphrase: {error}")))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Returns the default passphrase file belonging to a parent certificate.
///
/// Parent certificate shape: `<profile>/<kind>/<name>/ca/certs/ca.cert.pem`.
/// The parent CA directory is two ancestors above `certs/ca.cert.pem`, so the
/// default passphrase shape is `<parent-ca>/private/ca.passphrase`.
///
/// # Arguments
///
/// * `certificate` - Resolved parent certificate path.
///
/// # Returns
///
/// The default parent passphrase path.
///
/// # Errors
///
/// This function does not perform I/O and therefore returns no errors.
fn parent_default_passphrase(certificate: &Path) -> PathBuf {
    certificate
        .parent()
        .and_then(Path::parent)
        .map(|ca| ca.join("private/ca.passphrase"))
        .unwrap_or_else(|| PathBuf::from("private/ca.passphrase"))
}

fn read_passphrase(dir: &Path, path: &Path) -> Result<String, (u8, String)> {
    let full = if path.is_absolute() {
        path.to_path_buf()
    } else {
        dir.join(path)
    };
    let metadata =
        fs::symlink_metadata(&full).map_err(|_| (4, "cannot inspect passphrase file".into()))?;
    if !metadata.is_file() {
        return Err((4, "passphrase file must be a regular file".into()));
    }
    let value = fs::read_to_string(full).map_err(|_| (4, "cannot read passphrase file".into()))?;
    let value = value.trim_end_matches(['\r', '\n']).to_owned();
    if value.is_empty() || value.contains('\n') {
        return Err((4, "passphrase file must contain one nonempty line".into()));
    }
    Ok(value)
}

#[derive(Debug, Clone)]
struct ResolvedIssuer {
    path: PathBuf,
    profile: Profile,
}

fn resolve_issuer(dir: &Path, selector: &str) -> Result<ResolvedIssuer, (u8, String)> {
    let candidates = Profile::all()
        .into_iter()
        .filter_map(|profile| {
            let path = if selector == "root" {
                dir.join(profile.text()).join("root/ca/certs/ca.cert.pem")
            } else if let Some(name) = selector.strip_prefix("root:") {
                validate_name(name).ok()?;
                dir.join(profile.text())
                    .join("root")
                    .join(name)
                    .join("ca/certs/ca.cert.pem")
            } else if let Some(name) = selector.strip_prefix("intermediate:") {
                validate_name(name).ok()?;
                dir.join(profile.text())
                    .join("intermediate")
                    .join(name)
                    .join("ca/certs/ca.cert.pem")
            } else {
                return None;
            };
            path.is_file().then_some(ResolvedIssuer { path, profile })
        })
        .collect::<Vec<_>>();
    if candidates.len() == 1 {
        return Ok(candidates.into_iter().next().unwrap());
    }
    if candidates.len() > 1 {
        let paths = candidates
            .iter()
            .map(|candidate| candidate.path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err((
            4,
            format!("issuer selector is ambiguous: {selector} ({paths})"),
        ));
    }
    if !matches!(selector, "root")
        && !selector.starts_with("root:")
        && !selector.starts_with("intermediate:")
    {
        return Err((
            4,
            "issuer must be root, root:<name>, or intermediate:<name>".into(),
        ));
    }
    Err((
        4,
        format!("issuer certificate does not exist for selector: {selector}"),
    ))
}

fn intermediate_extension_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(".pki-intermediate-ext").join(name)
}

fn write_extension(dir: &Path, name: &str, pathlen: u32) -> Result<PathBuf, (u8, String)> {
    let file = intermediate_extension_path(dir, name);
    fs::create_dir_all(file.parent().unwrap()).map_err(fs_error)?;
    write_new(&file, &format!("basicConstraints=critical,CA:TRUE,pathlen:{pathlen}\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")).map_err(fs_error)?;
    Ok(file)
}

fn write_leaf_extension(target: &Path, sans: &[String]) -> Result<PathBuf, (u8, String)> {
    let file = target.join("config/leaf-ext.cnf");
    let values = sans
        .iter()
        .map(|value| {
            if value.parse::<IpAddr>().is_ok() {
                format!("IP:{value}")
            } else {
                format!("DNS:{value}")
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    write_new(&file, &format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName={values}\n")).map_err(fs_error)?;
    Ok(file)
}

fn write_chain(target: &Path, issuer: &Path, cert: &Path) -> Result<(), std::io::Error> {
    let issuer_bytes = fs::read(issuer)?;
    let cert_bytes = fs::read(cert)?;
    fs::write(target.join("chain/issuer-chain.pem"), &issuer_bytes)?;
    let mut full = cert_bytes;
    full.extend(issuer_bytes);
    fs::write(target.join("chain/fullchain.pem"), full)
}

fn normalize_sans(args: &CertArgs) -> Result<Vec<String>, (u8, String)> {
    let mut values = args
        .san
        .iter()
        .chain(args.dns.iter())
        .chain(args.ip.iter())
        .cloned()
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    if values.is_empty() {
        return Err((4, "at least one --san is required".into()));
    }
    for value in &values {
        if value.parse::<IpAddr>().is_err()
            && (value.is_empty()
                || value.contains('@')
                || value.contains('/')
                || value.contains(' '))
        {
            return Err((4, format!("invalid SAN: {value}")));
        }
    }
    Ok(values)
}

fn validate_subject(subject: &SubjectArgs) -> Result<(), (u8, String)> {
    if subject.common_name.trim().is_empty()
        || subject
            .organization
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
    {
        return Err((4, "common name and organization are required".into()));
    }
    if let Some(country) = &subject.country
        && country.len() != 2
    {
        return Err((4, "country must be two letters".into()));
    }
    Ok(())
}

fn validate_name(value: &str) -> Result<(), (u8, String)> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err((
            4,
            "name must contain only ASCII letters, digits, '-' or '_'".into(),
        ));
    }
    Ok(())
}

/// Converts and validates a user-provided certificate duration.
///
/// Input shape: a parsed duration such as amount `5` plus unit `Years`.
/// Output shape: one integer day count that can be passed to OpenSSL.
/// Validation happens after conversion so a value such as `1000y` cannot
/// bypass the command-specific maximum by having a small numeric amount.
///
/// # Arguments
///
/// * `duration` - Parsed duration from a command-line option.
/// * `minimum` - Smallest permitted number of days.
/// * `maximum` - Largest permitted number of days.
///
/// # Returns
///
/// The validated number of days.
///
/// # Errors
///
/// Returns an error when conversion overflows or the result is outside the allowed range.
fn normalized_days(
    duration: &CertificateDuration,
    minimum: u32,
    maximum: u32,
) -> Result<u32, (u8, String)> {
    let days = duration.to_days().map_err(|error| (4, error))?;
    if (minimum..=maximum).contains(&days) {
        Ok(days)
    } else {
        Err((
            4,
            format!("days must be in {minimum}..={maximum}; received {days}"),
        ))
    }
}

fn success_with_path(message: &str, dry_run: bool, path: String) -> Report {
    let mut report = success(message, dry_run);
    report.paths.push(path);
    report
}

/// Builds the root CA OpenSSL commands without executing them.
///
/// Input shape: root options, key/certificate paths, and normalized days.
/// Output shape: two argument arrays: one for key generation and one for
/// self-signed certificate creation. Password values are represented by a
/// passphrase-file placeholder because this output is safe to display.
///
/// # Arguments
///
/// * `args` - Root CA command-line options.
/// * `key` - Final private-key path.
/// * `cert` - Final certificate path.
/// * `days` - Integer lifetime passed to OpenSSL.
///
/// # Returns
///
/// Sanitized command argument arrays suitable for a dry-run report.
///
/// # Errors
///
/// This function does not perform fallible I/O and therefore returns no errors.
fn root_command_plan(args: &RootArgs, key: &Path, cert: &Path, days: u32) -> Vec<Vec<String>> {
    let key_command = if matches!(args.profile, Profile::Rsa4096) {
        vec![
            "openssl".into(),
            "genrsa".into(),
            "-aes256".into(),
            "-passout".into(),
            "file:<generated-or-supplied-passphrase>".into(),
            "-out".into(),
            key.display().to_string(),
            "4096".into(),
        ]
    } else if matches!(args.profile, Profile::EcdsaP256) {
        vec![
            "openssl".into(),
            "ecparam".into(),
            "-name".into(),
            "prime256v1".into(),
            "-genkey".into(),
            "-noout".into(),
            "-out".into(),
            key.display().to_string(),
        ]
    } else {
        vec![
            "openssl".into(),
            "genpkey".into(),
            "-algorithm".into(),
            "ED25519".into(),
            "-out".into(),
            key.display().to_string(),
        ]
    };
    let mut certificate_command = vec![
        "openssl".into(),
        "req".into(),
        "-x509".into(),
        "-new".into(),
        "-key".into(),
        key.display().to_string(),
    ];
    if matches!(args.profile, Profile::Rsa4096) {
        certificate_command.extend([
            "-passin".into(),
            "file:<generated-or-supplied-passphrase>".into(),
        ]);
    }
    certificate_command.extend([
        "-sha256".into(),
        "-days".into(),
        days.to_string(),
        "-subj".into(),
        args.subject.distinguished_name(),
        "-addext".into(),
        format!("basicConstraints=critical,CA:TRUE,pathlen:{}", args.pathlen),
        "-addext".into(),
        "keyUsage=critical,keyCertSign,cRLSign".into(),
        "-out".into(),
        cert.display().to_string(),
    ]);
    vec![key_command, certificate_command]
}

/// Lists the files and directories a root CA execution would publish.
///
/// Input shape: the absolute PKI root, the absolute CA target, and whether a
/// generated passphrase file will be needed. Output shape: relative paths that
/// are safe to display and serialize in reports.
///
/// # Arguments
///
/// * `dir` - The user-selected PKI root directory.
/// * `target` - The final root CA directory.
/// * `includes_passphrase` - Whether execution will generate a passphrase file.
///
/// # Returns
///
/// Relative planned artifact paths in stable creation order.
///
/// # Errors
///
/// This function does not perform fallible I/O and therefore returns no errors.
fn root_artifact_plan(dir: &Path, target: &Path, includes_passphrase: bool) -> Vec<String> {
    let mut artifacts = vec![
        relative_path(dir, &target.join("private/ca.key.pem")),
        relative_path(dir, &target.join("certs/ca.cert.pem")),
        relative_path(dir, &target.join("config/ca.ext")),
        relative_path(dir, &target.join("index.txt")),
        relative_path(dir, &target.join("serial")),
    ];
    if includes_passphrase {
        artifacts.push(relative_path(dir, &target.join("private/ca.passphrase")));
    }
    artifacts
}

#[allow(clippy::too_many_arguments)]
fn intermediate_command_plan(
    profile: &Profile,
    key: &Path,
    csr: &Path,
    cert: &Path,
    parent_cert: &Path,
    parent_key: &Path,
    extension: &Path,
    subject: &SubjectArgs,
    days: u32,
) -> Vec<Vec<String>> {
    let key_command = if matches!(profile, Profile::Rsa4096) {
        vec![
            "openssl".into(),
            "genrsa".into(),
            "-aes256".into(),
            "-passout".into(),
            "file:<child-passphrase>".into(),
            "-out".into(),
            key.display().to_string(),
            "4096".into(),
        ]
    } else if matches!(profile, Profile::EcdsaP256) {
        vec![
            "openssl".into(),
            "ecparam".into(),
            "-name".into(),
            "prime256v1".into(),
            "-genkey".into(),
            "-noout".into(),
            "-out".into(),
            key.display().to_string(),
        ]
    } else {
        vec![
            "openssl".into(),
            "genpkey".into(),
            "-algorithm".into(),
            "ED25519".into(),
            "-out".into(),
            key.display().to_string(),
        ]
    };
    let csr_command = vec![
        "openssl".into(),
        "req".into(),
        "-new".into(),
        "-key".into(),
        key.display().to_string(),
        "-passin".into(),
        "file:<child-passphrase>".into(),
        "-subj".into(),
        subject.distinguished_name(),
        "-out".into(),
        csr.display().to_string(),
    ];
    let signing_command = vec![
        "openssl".into(),
        "x509".into(),
        "-req".into(),
        "-in".into(),
        csr.display().to_string(),
        "-CA".into(),
        parent_cert.display().to_string(),
        "-CAkey".into(),
        parent_key.display().to_string(),
        "-passin".into(),
        "file:<parent-passphrase>".into(),
        "-days".into(),
        days.to_string(),
        "-set_serial".into(),
        "1000".into(),
        "-extfile".into(),
        extension.display().to_string(),
        "-out".into(),
        cert.display().to_string(),
    ];
    vec![key_command, csr_command, signing_command]
}

#[allow(clippy::too_many_arguments)]
fn certificate_command_plan(
    profile: &Profile,
    key: &Path,
    csr: &Path,
    cert: &Path,
    issuer_cert: &Path,
    issuer_key: &Path,
    extension: &Path,
    subject: &SubjectArgs,
    days: u32,
) -> Vec<Vec<String>> {
    let key_command = if matches!(profile, Profile::Rsa4096) {
        vec![
            "openssl".into(),
            "genrsa".into(),
            "-aes256".into(),
            "-passout".into(),
            "file:<leaf-passphrase>".into(),
            "-out".into(),
            key.display().to_string(),
            "4096".into(),
        ]
    } else if matches!(profile, Profile::EcdsaP256) {
        vec![
            "openssl".into(),
            "ecparam".into(),
            "-name".into(),
            "prime256v1".into(),
            "-genkey".into(),
            "-noout".into(),
            "-out".into(),
            key.display().to_string(),
        ]
    } else {
        vec![
            "openssl".into(),
            "genpkey".into(),
            "-algorithm".into(),
            "ED25519".into(),
            "-out".into(),
            key.display().to_string(),
        ]
    };
    let csr_command = vec![
        "openssl".into(),
        "req".into(),
        "-new".into(),
        "-key".into(),
        key.display().to_string(),
        "-passin".into(),
        "file:<leaf-passphrase>".into(),
        "-subj".into(),
        subject.distinguished_name(),
        "-out".into(),
        csr.display().to_string(),
    ];
    let signing_command = vec![
        "openssl".into(),
        "x509".into(),
        "-req".into(),
        "-in".into(),
        csr.display().to_string(),
        "-CA".into(),
        issuer_cert.display().to_string(),
        "-CAkey".into(),
        issuer_key.display().to_string(),
        "-passin".into(),
        "file:<issuer-passphrase>".into(),
        "-days".into(),
        days.to_string(),
        "-set_serial".into(),
        "1001".into(),
        "-extfile".into(),
        extension.display().to_string(),
        "-out".into(),
        cert.display().to_string(),
    ];
    vec![key_command, csr_command, signing_command]
}

fn certificate_artifact_plan(dir: &Path, target: &Path, includes_passphrase: bool) -> Vec<String> {
    let mut artifacts = vec![
        relative_path(dir, &target.join("private/key.pem")),
        relative_path(dir, &target.join("csr/request.csr.pem")),
        relative_path(dir, &target.join("certs/cert.pem")),
        relative_path(dir, &target.join("config/leaf-ext.cnf")),
        relative_path(dir, &target.join("chain/issuer-chain.pem")),
        relative_path(dir, &target.join("chain/fullchain.pem")),
    ];
    if includes_passphrase {
        artifacts.push(relative_path(dir, &target.join("private/passphrase")));
    }
    artifacts
}

fn intermediate_artifact_plan(
    dir: &Path,
    target: &Path,
    extension: &Path,
    includes_passphrase: bool,
) -> Vec<String> {
    let mut artifacts = vec![
        relative_path(dir, &target.join("private/ca.key.pem")),
        relative_path(dir, &target.join("csr/ca.csr.pem")),
        relative_path(dir, &target.join("certs/ca.cert.pem")),
        relative_path(dir, extension),
        relative_path(dir, &target.join("index.txt")),
        relative_path(dir, &target.join("serial")),
        relative_path(dir, &target.join("chain/issuer-chain.pem")),
        relative_path(dir, &target.join("chain/fullchain.pem")),
    ];
    if includes_passphrase {
        artifacts.push(relative_path(dir, &target.join("private/ca.passphrase")));
    }
    artifacts
}

fn print_planned_root(report: &Report) {
    if !report.planned_commands.is_empty() {
        let label = if report
            .planned_artifacts
            .iter()
            .any(|artifact| artifact.contains("/intermediate/"))
        {
            "planned CA artifacts:"
        } else if report
            .planned_artifacts
            .iter()
            .any(|artifact| artifact.contains("/certs/") && artifact.contains("/csr/"))
        {
            "planned certificate artifacts:"
        } else {
            "planned root CA artifacts:"
        };
        println!("{label}");
        for artifact in &report.planned_artifacts {
            println!("  {artifact}");
        }
        println!("planned OpenSSL commands:");
        for command in &report.planned_commands {
            println!("  $ {}", command.join(" "));
        }
    }
}

fn write_new(path: &Path, contents: &str) -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(contents.as_bytes())
}

fn fs_error(error: std::io::Error) -> (u8, String) {
    (6, error.to_string())
}
fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn list_certificates(
    dir: &Path,
    openssl: &mut OpenSsl,
    verbose: bool,
) -> Result<Report, (u8, String)> {
    let mut paths = Vec::new();
    collect_certificates(dir, dir, &mut paths).map_err(|error| (6, error))?;
    paths.sort();
    let mut records = Vec::new();
    for path in paths {
        if verbose {
            let args = vec![
                "x509".into(),
                "-in".into(),
                path.display().to_string(),
                "-noout".into(),
                "-subject".into(),
                "-issuer".into(),
                "-serial".into(),
                "-dates".into(),
                "-fingerprint".into(),
                "-pubkey".into(),
            ];
            openssl.run(&args).map_err(|error| (10, error))?;
        }
        if let Ok(record) = parse_certificate(&path, dir) {
            records.push(record);
        }
    }
    if !verbose {
        let _ = openssl
            .run(&["x509".into(), "-help".into()])
            .map_err(|error| (10, error))?;
    }
    records.sort_by(|a, b| a.subject.cmp(&b.subject).then(a.path.cmp(&b.path)));
    let mut report = success(&format!("listed {} certificate(s)", records.len()), true);
    report.certificates = Some(records);
    Ok(report)
}

fn collect_certificates(
    root: &Path,
    current: &Path,
    result: &mut Vec<PathBuf>,
) -> Result<(), String> {
    for entry in fs::read_dir(current).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.is_dir() {
            collect_certificates(root, &path, result)?;
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        let relative = path.strip_prefix(root).unwrap_or(&path).to_string_lossy();
        if (name.ends_with(".pem") || name.ends_with(".crt") || name.ends_with(".cer"))
            && !relative.contains("/private/")
            && !name.contains("key")
            && !name.contains("csr")
            && !name.contains("chain")
        {
            result.push(path);
        }
    }
    Ok(())
}

fn parse_certificate(path: &Path, root: &Path) -> Result<CertificateRecord, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let (_, pem) = parse_x509_pem(&bytes).map_err(|_| "not PEM".to_owned())?;
    let cert = pem.parse_x509().map_err(|_| "not X.509".to_owned())?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .map(|value| value.as_str().unwrap_or_default().to_owned())
        .unwrap_or_else(|| "<no common name>".into());
    let domains = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(value) => Some((*value).into()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let relative = relative_path(root, path);
    let (name, kind, profile) = classify_certificate_path(&relative);
    Ok(CertificateRecord {
        path: relative,
        name,
        kind,
        profile,
        common_name,
        algorithm: format_algorithm(cert.public_key().algorithm.algorithm.to_string()),
        expires: format_timestamp(cert.validity().not_after.timestamp()),
        issuer,
        subject,
        domains,
    })
}

/// Builds a child subject by keeping explicit child values and inheriting omitted fields.
///
/// # Arguments
///
/// * `parent` - Subject values read from the parent certificate.
/// * `child` - Subject values supplied for the new intermediate.
///
/// # Returns
///
/// A complete subject for the intermediate certificate.
///
/// # Errors
///
/// This function does not perform fallible work.
fn inherited_subject(parent: &SubjectArgs, child: &SubjectArgs) -> SubjectArgs {
    SubjectArgs {
        common_name: child.common_name.clone(),
        organization: child
            .organization
            .clone()
            .or_else(|| parent.organization.clone()),
        organizational_unit: child
            .organizational_unit
            .clone()
            .or_else(|| parent.organizational_unit.clone()),
        country: child.country.clone().or_else(|| parent.country.clone()),
        state: child.state.clone().or_else(|| parent.state.clone()),
        locality: child.locality.clone().or_else(|| parent.locality.clone()),
    }
}

fn read_subject(path: &Path) -> Result<SubjectArgs, (u8, String)> {
    let bytes = fs::read(path).map_err(fs_error)?;
    let (_, pem) =
        parse_x509_pem(&bytes).map_err(|_| (4, "parent certificate is not PEM".into()))?;
    let certificate = pem
        .parse_x509()
        .map_err(|_| (4, "parent certificate is not X.509".into()))?;
    let subject = certificate.subject().to_string();
    let value = |prefix: &str| {
        subject
            .split(',')
            .map(str::trim)
            .find_map(|field| field.strip_prefix(prefix).map(str::to_owned))
    };
    Ok(SubjectArgs {
        common_name: value("CN=").unwrap_or_default(),
        organization: value("O="),
        organizational_unit: value("OU="),
        country: value("C="),
        state: value("ST="),
        locality: value("L="),
    })
}

fn classify_certificate_path(path: &str) -> (Option<String>, String, Option<String>) {
    let parts = path.split('/').collect::<Vec<_>>();
    if parts.len() >= 6 && parts[1] == "root" && parts[3] == "ca" && parts[4] == "certs" {
        return (
            Some(parts[2].to_owned()),
            "root_ca".into(),
            Some(parts[0].to_owned()),
        );
    }
    if parts.len() >= 6 && parts[1] == "intermediate" && parts[3] == "ca" && parts[4] == "certs" {
        return (
            Some(parts[2].to_owned()),
            "intermediate_ca".into(),
            Some(parts[0].to_owned()),
        );
    }
    if parts.len() >= 5 && parts[1] == "certs" && parts[3] == "certs" {
        return (
            Some(parts[2].to_owned()),
            "certificate".into(),
            Some(parts[0].to_owned()),
        );
    }
    (None, "unclassified".into(), None)
}

fn format_algorithm(value: String) -> String {
    if value.contains("1.2.840.113549.1.1") {
        "RSA".into()
    } else if value.contains("1.2.840.10045") {
        "ECDSA".into()
    } else if value.contains("1.3.101.112") {
        "Ed25519".into()
    } else {
        value
    }
}
fn format_timestamp(timestamp: i64) -> String {
    OffsetDateTime::from_unix_timestamp(timestamp)
        .map(|value| {
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02} UTC",
                value.year(),
                u8::from(value.month()),
                value.day(),
                value.hour(),
                value.minute()
            )
        })
        .unwrap_or_else(|_| format!("unix:{timestamp}"))
}
/// Renders every certificate as a deterministic issuer/subject hierarchy.
///
/// Input shape: a flat slice of successfully parsed certificate records.
/// Intermediate shape: a subject index and a parent-to-child adjacency map.
/// Output shape: one display line per input record, indented two spaces for
/// every issuer relationship level. Missing, ambiguous, and cyclic records
/// are emitted at the top level so inventory records are never hidden.
///
/// # Arguments
///
/// * `records` - Certificate records discovered by the list operation.
///
/// # Returns
///
/// Human-readable certificate lines joined with newline characters.
///
/// # Errors
///
/// This function does not perform fallible I/O and therefore returns no errors.
fn render_tree(records: &[CertificateRecord]) -> String {
    let mut subjects: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, record) in records.iter().enumerate() {
        subjects
            .entry(record.subject.clone())
            .or_default()
            .push(index);
    }

    let mut children: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut top_level = Vec::new();
    for (index, record) in records.iter().enumerate() {
        if record.issuer == record.subject {
            top_level.push(index);
            continue;
        }
        match subjects.get(&record.issuer) {
            Some(parents) if parents.len() == 1 => {
                children.entry(parents[0]).or_default().push(index);
            }
            _ => top_level.push(index),
        }
    }

    let sort_indices = |indices: &mut Vec<usize>| {
        indices.sort_by(|left, right| {
            display_sort_key(&records[*left]).cmp(&display_sort_key(&records[*right]))
        });
    };
    sort_indices(&mut top_level);
    for values in children.values_mut() {
        sort_indices(values);
    }

    let mut lines = Vec::new();
    let mut visited = std::collections::HashSet::new();
    for index in top_level {
        render_record_branch(index, 0, records, &children, &mut visited, &mut lines);
    }
    for index in 0..records.len() {
        if !visited.contains(&index) {
            render_record_branch(index, 0, records, &children, &mut visited, &mut lines);
        }
    }
    lines.join("\n")
}

fn display_sort_key(record: &CertificateRecord) -> (String, String, String, String, String) {
    (
        record.profile.clone().unwrap_or_default(),
        record.kind.clone(),
        record.name.clone().unwrap_or_default(),
        record.common_name.clone(),
        record.path.clone(),
    )
}

fn render_record_branch(
    index: usize,
    depth: usize,
    records: &[CertificateRecord],
    children: &HashMap<usize, Vec<usize>>,
    visited: &mut std::collections::HashSet<usize>,
    lines: &mut Vec<String>,
) {
    if !visited.insert(index) {
        return;
    }
    let record = &records[index];
    let name = record.name.as_deref().unwrap_or("<unnamed>");
    lines.push(format!(
        "{}{} ({}) — {} [{}] — expires {}",
        "  ".repeat(depth),
        name,
        record.kind,
        record.common_name,
        record.algorithm,
        record.expires
    ));
    if let Some(record_children) = children.get(&index) {
        for child in record_children {
            render_record_branch(*child, depth + 1, records, children, visited, lines);
        }
    }
}
fn print_verbose_commands(commands: &[CommandReport]) {
    for command in commands {
        println!("$ {}", command.argv.join(" "));
        println!(
            "status: {} (exit code: {:?})",
            command.success, command.code
        );
        println!(
            "stdout:\n{}",
            if command.stdout.is_empty() {
                "<empty>"
            } else {
                &command.stdout
            }
        );
        println!(
            "stderr:\n{}",
            if command.stderr.is_empty() {
                "<empty>"
            } else {
                &command.stderr
            }
        );
    }
}
