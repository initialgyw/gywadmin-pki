# gywadmin-pki

`pki` is a Unix-only command-line tool for managing an offline public-key infrastructure (PKI) with the OpenSSL CLI.

It can create:

- Root certificate authorities (CAs).
- Intermediate CAs, including nested intermediates.
- Leaf certificates signed by a root or intermediate CA.
- Certificate signing requests (CSRs) and certificate-chain bundles.

The tool is deliberately conservative:

- Commands are dry runs by default.
- A command-local `--do-it` is required after a selected create subcommand before files or CA databases are changed.
- Existing targets are never overwritten.
- Private keys are encrypted.
- Passphrases are read from existing files and passed to OpenSSL through a file descriptor instead of a command-line argument.
- OpenSSL CA databases are locked, snapshotted, and recoverable after failures.

## Table of contents

- [Requirements](#requirements)
- [Docker image](#docker-image)
  - [Build for both architectures](#build-for-both-architectures)
  - [Prepare a Docker PKI directory](#prepare-a-docker-pki-directory)
  - [Run the container](#run-the-container)
- [Global options](#global-options)
- [First use: dry run before execution](#first-use-dry-run-before-execution)
- [Passphrase files](#passphrase-files)
- [Check OpenSSL](#check-openssl)
- [Create a root CA](#create-a-root-ca)
- [Create an intermediate CA](#create-an-intermediate-ca)
  - [Root-signed intermediate](#root-signed-intermediate)
  - [Nested intermediate](#nested-intermediate)
- [Create a certificate signed by the root](#create-a-certificate-signed-by-the-root)
- [Create a certificate signed by an intermediate](#create-a-certificate-signed-by-an-intermediate)
- [Certificate options](#certificate-options)
- [SAN rules](#san-rules)
- [Output layout](#output-layout)
- [Verbose reporting](#verbose-reporting)
- [JSON output](#json-output)
- [Recovery after rollback failure](#recovery-after-rollback-failure)
- [Exit codes](#exit-codes)
- [Docker troubleshooting](#docker-troubleshooting)
  - [Permission denied on `/data/pki`](#permission-denied-on-datapki)
  - [Passphrase file rejected](#passphrase-file-rejected)
  - [OpenSSL unavailable](#openssl-unavailable)
  - [Need a shell inside the runtime image](#need-a-shell-inside-the-runtime-image)
- [Docker lifecycle validation](#docker-lifecycle-validation)

## Requirements

- Unix-like operating system.
- OpenSSL with Ed25519 support.
- Docker is recommended because the host does not need a Rust installation.
- Docker builds target `linux/amd64` and `linux/arm64`.

The application invokes `openssl` at runtime. It does not use a Rust OpenSSL library as a replacement for the OpenSSL executable.

## Docker image

The Dockerfile uses a multi-stage Alpine build:

- The `builder` stage uses the pinned Rust Alpine image, OpenSSL development packages, Cargo.lock, Rustfmt, Clippy, unit tests, integration tests, and a release build.
- The `runtime` stage uses Alpine only, installs `openssl` and `ca-certificates`, and copies `/usr/local/bin/pki`.
- The runtime image does not contain Rust, Cargo, a compiler, source files, tests, or build caches.
- The runtime executes as UID/GID `10001:10001`.
- The runtime entrypoint is `/usr/local/bin/pki`.
- No Docker `VOLUME` is declared. Mount PKI data explicitly at `/data/pki`.

### Build for both architectures

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag gywadmin-pki:local \
  .
```

A multi-platform build is not automatically loaded into the local Docker image store. To build and load an image for the current machine:

```sh
docker buildx build \
  --platform linux/arm64 \
  --load \
  --tag gywadmin-pki:local \
  .
```

Use `linux/amd64` instead when building on an AMD64 machine.

### Prepare a Docker PKI directory

The runtime container runs as UID/GID `10001:10001`, so the mounted directory must be accessible to that user:

```sh
mkdir -m 700 pki
sudo chown -R 10001:10001 pki
```

Do not mount, access, or modify `/Volumes/gywadmin-homelab/pki` or any production offline-PKI path from Docker. Use a disposable directory while learning or testing.

### Run the container

Because the image already has `pki` as its entrypoint, pass CLI arguments after the image name:

```sh
docker run --rm \
  --mount "type=bind,src=$PWD/pki,dst=/data/pki" \
  gywadmin-pki:local \
  --dir /data/pki \
  check
```

Show help:

```sh
docker run --rm gywadmin-pki:local --help
```

Open a shell for troubleshooting:

```sh
docker run --rm \
  --entrypoint /bin/sh \
  gywadmin-pki:local
```

Check the runtime OpenSSL installation:

```sh
docker run --rm \
  --entrypoint /bin/sh \
  gywadmin-pki:local \
  -c 'id; command -v openssl; openssl version'
```

## Release process

Every pull request that changes the project must manually bump the package version in `Cargo.toml`. The version must be a stable `MAJOR.MINOR.PATCH` SemVer value greater than the version on `main`, and the root `gywadmin-pki` package version in `Cargo.lock` must match it. The version validation workflow rejects unchanged, downgraded, malformed, or lockfile-mismatched versions. Configure the `Version / Validate version bump` workflow as a required pull-request status check in branch protection.

After a version-bumped pull request is merged into `main`, the release workflow reads the version from the exact merge commit and creates the corresponding immutable tag, such as `v0.1.1`. Existing tags are never moved. A matching release tag triggers the container workflow, which builds and publishes both `linux/amd64` and `linux/arm64` images to GitHub Container Registry:

```text
ghcr.io/initialgyw/gywadmin-pki:0.1.1
ghcr.io/initialgyw/gywadmin-pki:latest
```

The `latest` tag is updated for stable releases. The workflows require repository Actions permissions that allow `contents: write` for release tagging and `packages: write` for GHCR publishing. If a tag workflow reports that a version already exists at another commit, bump the package version again rather than moving the existing tag.

## Global options

The global options appear before the subcommand:

```text
pki [OPTIONS] --dir <DIR> <COMMAND>
```

| Option | Description |
|---|---|
| `--dir <DIR>` | Existing offline PKI root directory. Required. |
| `-v`, `--verbose` | Show additional sanitized diagnostics. |
| `--openssl-binary <PATH>` | OpenSSL executable to use. Defaults to `openssl` from `PATH`. |
| `--output human` | Human-readable output. Default. |
| `--output json` | Machine-readable JSON output. |
| `--json` | Shortcut for `--output json`. |
| `-h`, `--help` | Show help. |
| `-V`, `--version` | Show the version. |

Global options must appear before the subcommand. `--do-it` is not global: it is accepted only by `create-ca` and `create-cert`, and must appear after that selected subcommand. `check --do-it` is rejected. For example:

```sh
pki --dir ./pki --output json check
pki --dir ./pki create-ca --name example-root --common-name "Example Root CA" --organization Example --do-it
```

## First use: dry run before execution

All create commands are dry runs unless their command-local `--do-it` flag is present:

```sh
pki --dir ./pki \
  create-ca \
  --name example-root \
  --profile ed25519 \
  --common-name "Example Root CA" \
  --organization Example \
  --passphrase-file root.pass
# or: --passphrase PROMPT
# or: --passphrase NONE
# or: --passphrase-file AUTO
```

A dry run:

- Validates arguments and subjects.
- Shows planned OpenSSL commands and artifacts for root, intermediate, and leaf creation.
- Validates paths and passphrase files.
- Checks the configured OpenSSL executable.
- Shows the planned root artifacts and sanitized OpenSSL commands.
- Shows normalized certificate lifetime in days.
- Checks issuer and CA state where applicable.
- Does not create directories, keys, CSRs, certificates, locks, passphrases, or CA database changes.

For example, a root dry run reports commands such as `openssl ecparam ...` and `openssl req -x509 ... -days 1825`, but does not execute them. Password values are never shown. RSA previews use a placeholder for the passphrase file; ECDSA and Ed25519 keys do not require one.

After reviewing the dry-run output, repeat the command with `--do-it` after the selected create subcommand and its arguments.

## Passphrase selection

Every `create-ca` and `create-cert` command requires exactly one of `--passphrase` or `--passphrase-file`. The options cannot be combined.

`--passphrase` accepts:

- A literal single-line passphrase. It is saved to the artifact's default passphrase file.
- `PROMPT`, which reads a masked passphrase twice and saves the confirmed value.
- `NONE`, which creates an unencrypted private key and no passphrase file.

`--passphrase-file` accepts:

- An existing passphrase file. Its contents are validated and copied to the artifact's default passphrase file.
- `AUTO`, which generates a 256-bit passphrase and saves it to the default passphrase file.

The control values are uppercase and case-sensitive. `PROMPT` requires an interactive terminal. Dry runs never prompt, generate secrets, copy files, or create artifacts. The selector protects the newly generated key; parent and issuer passphrases remain separate and are loaded from their existing passphrase files or explicit override options.

A passphrase file must be a regular, nonempty, single-line file. Passphrase values are never placed in OpenSSL arguments, reports, or logs. `NONE` intentionally reduces private-key protection at rest.

A passphrase file must be:

- A regular file.
- Not a symlink.
- Inside the `--dir` directory.
- Owned by the current effective user.
- Nonempty and a single line.
- Mode `0600` or stricter.

Create one locally:

```sh
printf 'root-secret\n' > pki/root.pass
chmod 600 pki/root.pass
```

For the Docker runtime, ensure the container user owns it:

```sh
sudo chown 10001:10001 pki/root.pass
chmod 600 pki/root.pass
```

Relative passphrase paths are resolved relative to `--dir`:

```text
--dir ./pki --passphrase-file root.pass
# or: --passphrase PROMPT
# or: --passphrase NONE
# or: --passphrase-file AUTO
```

Absolute paths are accepted only if they remain beneath `--dir`.

Passphrase contents are never placed in OpenSSL arguments, reports, or logs. Encrypted RSA key operations pass the passphrase through a protected passphrase file using OpenSSL's `file:` input syntax; the passphrase value itself is never placed in the process argument list. ECDSA and Ed25519 keys are generated without passphrase input.

## Learning the Rust implementation

The executable is implemented in `src/main.rs`. A useful way to read it is to follow the data flow:

1. `main` parses command-line arguments with Clap.
2. `execute` validates the directory and dispatches to the selected operation.
3. `list_certificates` discovers certificate files and parses them into `CertificateRecord` values.
4. `OpenSsl::run` invokes OpenSSL with `std::process::Command` and records stdout, stderr, and exit status.
5. `render_tree` organizes records by matching each certificate issuer to another certificate subject.
6. `print_verbose_commands` prints the captured OpenSSL logs before the final inventory.

Rust syntax to notice:

- `&Path` and `&str` are borrowed views; they let a function read data without taking ownership.
- `&mut OpenSsl` is a mutable borrow; it allows a function to append command reports.
- `Result<T, E>` represents either success (`Ok(T)`) or failure (`Err(E)`).
- `?` returns an error early from the current function when a `Result` contains `Err`.
- `Vec<T>` is an owned, growable list. `Vec<&T>` stores references to existing values instead of copying them.
- `match` makes each success and failure branch explicit.

### Comments and data-shape notes

The source includes rustdoc on functions and structural comments before the main transformations. When reading a function, first identify its input shape, then the intermediate values it creates, and finally the returned output shape.

## Check OpenSSL

Native:

```sh
pki --dir ./pki check
```

Docker:

```sh
docker run --rm \
  --mount "type=bind,src=$PWD/pki,dst=/data/pki" \
  gywadmin-pki:local \
  --dir /data/pki \
  check
```

`check` verifies that OpenSSL is available and that the configured OpenSSL installation supports the Ed25519 operations required by the tool. It does not modify the PKI directory.

## Create a CA

Use `create-ca` for both root and intermediate CAs. The presence of `--parent` determines the kind:

- Without `--parent`, the command creates a self-signed root CA.
- With `--parent`, the command creates an intermediate CA signed by that parent.


### Root CA

A root CA is self-signed and becomes the trust anchor for its profile.

Dry run:

```sh
pki --dir ./pki \
  create-ca \
  --name example-root \
  --profile ed25519 \
  --common-name "Example Root CA" \
  --organization Example \
  --passphrase-file root.pass
# or: --passphrase PROMPT
# or: --passphrase NONE
# or: --passphrase-file AUTO
```

Execute:

```sh
pki --dir ./pki \
  create-ca --do-it \
  --name example-root \
  --profile ed25519 \
  --common-name "Example Root CA" \
  --organization Example \
  --passphrase-file root.pass
# or: --passphrase PROMPT
# or: --passphrase NONE
# or: --passphrase-file AUTO
```

Important options:

| Option | Description | Default |
|---|---|---:|
| `--name` | Required globally unique safe directory name across all root and intermediate CAs and profiles. | — |
| `--profile` | `ecdsa-p256`, `ed25519`, or `rsa-4096` | `ecdsa-p256` |
| `--common-name` | Required CA common name. `--cn` is an alias. | — |
| `--organization` | Required organization name. | — |
| `--days` | Lifetime as days or `d`, `w`, `m`, or `y`; bare numbers mean days. `1m` is 30 days and `1y` is 365 days. | `5y` |
| `--pathlen` | Optional maximum permitted subordinate CA depth. Omitted means no explicit path-length constraint; use `--pathlen 0` to forbid subordinate CAs. | omitted |
| `--passphrase-file` | Existing file for the encrypted root key, or omit to generate `<dir>/<profile>/root/<name>/ca/private/ca.passphrase` during execution. | generated when omitted |
| `--do-it` | Execute this root CA operation; place it after `create-ca`. | dry run |

The root is stored at:

```text
<dir>/<profile>/root/<name>/ca/
```

CA names are globally unique across all root and intermediate CAs and profiles. Existing legacy roots at `<dir>/<profile>/root/ca/` remain readable through the selector `root`; named roots use `root:<name>`. A name collision returns exit code 5 and identifies the existing CA.

## Create an intermediate CA

An intermediate CA is signed by a parent CA. The parent can be the root or another intermediate.

### Root-signed intermediate

```sh
pki --dir ./pki \
  create-ca --do-it \
  --profile ed25519 \
  --name issuing \
  --parent root \
  --common-name "Example Issuing CA" \
  --organization Example \
   --pathlen 0 \
   --passphrase-file issuing.pass \
   --parent-passphrase-file root.pass
```

### Nested intermediate

```sh
pki --dir ./pki \
  create-ca --do-it \
  --profile ed25519 \
  --name nested \
  --parent intermediate:issuing \
  --common-name "Example Nested CA" \
  --organization Example \
   --pathlen 0 \
   --passphrase-file nested.pass \
   --parent-passphrase-file issuing.pass
```

Important options:

| Option | Description | Default |
|---|---|---:|
| `--profile` | Optional key profile. If omitted, the immediate parent CA profile is inherited; an explicit profile must match the parent. | inherited from parent |
| `--name` | Globally unique safe directory name across all root and intermediate CAs and profiles. | — |
| `--parent` | `root`, `root:<name>`, or `intermediate:<name>`. The parent profile is used when `--profile` is omitted. | — |
| `--common-name` | Required CA common name. `--cn` is an alias. | — |
| `--organization` | Optional organization name; inherited from the parent when omitted. | inherited from parent |
| `--organizational-unit` | Optional OU; inherited from the parent when omitted. | inherited from parent |
| `--country` | Optional country; inherited from the parent when omitted. | inherited from parent |
| `--state` | Optional state; inherited from the parent when omitted. | inherited from parent |
| `--locality` | Optional locality; inherited from the parent when omitted. | inherited from parent |
| `--days` | Lifetime as days or `d`, `w`, `m`, or `y`; bare numbers mean days. | `2y` |
| `--pathlen` | Optional permitted subordinate CA depth. Omission defaults to `0` for intermediate CAs. | `0` |
| `--passphrase-file` | Passphrase file for the new intermediate CA key, or omit to generate `private/ca.passphrase` during execution. | generated when omitted |
| `--parent-passphrase-file` | Passphrase file for the existing parent CA key. If omitted, use the parent's `private/ca.passphrase`. | parent default |
| `--do-it` | Execute this intermediate CA operation; place it after `create-ca`. | dry run |

Intermediate CAs are stored at:

```text
<dir>/<profile>/intermediate/<name>/ca/
```

The child must not outlive its issuer. Its path length must be lower than the issuer’s available path length. CA names are globally unique, so parent selectors resolve to one CA across the supported profile directories; pre-existing ambiguous layouts still fail instead of choosing a parent arbitrarily. Intermediate dry runs also show the planned key-generation, CSR, and signing OpenSSL commands, planned artifacts, inherited profile, and normalized lifetime without creating files.

## Create a certificate signed by the root

```sh
pki --dir ./pki \
  create-cert --do-it \
  --root \
  --profile ed25519 \
  --name service \
  --common-name service.example.com \
  --organization Example \
  --san service.example.com \
  --san 192.0.2.10 \
  --san 2001:db8::10 \
  --passphrase-file service.pass \
  --issuer-passphrase-file root.pass
```

Use `--issuer root` for the legacy root, `--issuer root:<name>` for a named root, or `--issuer intermediate:<name>` for an intermediate. The issuer's profile and omitted subject fields are inherited automatically.

## Create a certificate signed by an intermediate

```sh
pki --dir ./pki \
  create-cert --do-it \
  --issuer intermediate:issuing \
  --profile ed25519 \
  --name service \
  --common-name service.example.com \
  --organization Example \
  --san service.example.com \
  --san 192.0.2.10 \
  --passphrase-file service.pass \
  --issuer-passphrase-file issuing.pass
```

Use exactly one issuer selector:

- `--issuer root` for the legacy root-signed certificate.
- `--issuer root:<name>` for a named-root-signed certificate.
- `--issuer intermediate:<name>` for an intermediate-signed certificate.

`--name` is the leaf certificate directory name. `--issuer-passphrase-file` is required because the issuer’s encrypted private key must be unlocked for signing.

## Certificate options

| Option | Description |
|---|---|
| `--issuer` | Required selector: `root`, `root:<name>`, or `intermediate:<name>`. |
| `--profile` | Optional; inherited from the issuer when omitted. |
| `--name` | Safe output directory name. |
| `--common-name` | Required subject common name. `--cn` is an alias. |
| `--organization` | Optional; inherited from the issuer when omitted. |
| `--organizational-unit` | Optional; inherited from the issuer when omitted. |
| `--country` | Optional; inherited from the issuer when omitted. |
| `--state` | Optional; inherited from the issuer when omitted. |
| `--locality` | Optional; inherited from the issuer when omitted. |
| `--days` | Leaf lifetime as days or `d`, `w`, `m`, or `y`; bare numbers mean days. Maximum: `397` days. |
| `--san` | Repeatable DNS name or IP address. At least one is required. |
| `--passphrase-file` | Optional leaf passphrase file; otherwise a secure random passphrase is generated under the leaf's `private/` directory. |
| `--issuer-passphrase-file` | Optional issuer passphrase file; otherwise use the issuer's `private/ca.passphrase`. |
| `--do-it` | Execute this certificate operation; place it after `create-cert`. |

## SAN rules

Only DNS and IP SANs are supported:

```sh
--san service.example.com
--san '*.example.com'
--san 192.0.2.10
--san 2001:db8::10
```

The tool:

- Requires at least one SAN for leaf certificates.
- Validates DNS labels.
- Validates IPv4 and IPv6 addresses.
- Removes duplicate SAN values.
- Rejects URI, email, and other SAN types.
- Checks the generated certificate against the requested SAN set.

The common name does not replace SAN validation.

## List output

Human `list` output includes the logical name used by `--name` for recognized intermediate CAs and certificates. Certificates are indented beneath their issuer: intermediate CAs appear under roots, and leaf certificates appear under their intermediate or directly under a root when root-signed. Unresolved records remain visible at the top level. JSON output is selected with either `--json` or `--output json` before `list`:

```sh
pki --dir ./pki --json list
pki --dir ./pki --output json list
```

Recognized JSON records include `name`, `kind`, and `profile` fields. For example, an intermediate at `<profile>/intermediate/issuing/ca/` has `name: "issuing"` and `kind: "intermediate_ca"`; a leaf at `<profile>/certs/service/` has `name: "service"` and `kind: "certificate"`. Legacy roots and certificates outside the recognized layout use `name: null` rather than receiving a fabricated name.

## Output layout

```text
<dir>/
└── <profile>/
    ├── root/
    │   └── <name>/
    │       └── ca/
    │           ├── private/
    │           │   └── ca.passphrase (when generated)
    │           ├── certs/
    │           ├── config/
    │           ├── newcerts/
    │           ├── index.txt
    │           └── serial
    ├── intermediate/
    │   └── <name>/
    │       └── ca/
    └── certs/
        └── <name>/
            ├── private/
            │   └── key.pem
            ├── csr/
            │   └── request.csr.pem
            ├── certs/
            │   └── cert.pem
            └── chain/
                ├── issuer-chain.pem
                └── fullchain.pem
```

Leaf bundle order:

```text
issuer-chain.pem:
  immediate issuer
  higher non-root issuers
```

```text
fullchain.pem:
  leaf certificate
  immediate issuer
  higher non-root issuers
```

The root certificate is excluded from default leaf issuer-chain and fullchain files.

Private directories use mode `0700`. Private keys and CA database/configuration state use mode `0600`. Existing targets are not overwritten.

## Verbose reporting

Use `-v` or `--verbose` before the subcommand to add a safe execution report. Human output retains its normal success/error line and final target path; verbose mode then lists the root, intermediate, or leaf operation context, issuer/parent selector, sanitized OpenSSL argv, lifecycle phase (`preflight`, `validation`, or `execution`), success status, exit code or signal, and stdout/stderr byte counts.

```sh
pki --dir ./pki --verbose create-ca --do-it \
  --common-name "Example Root CA" --organization Example --passphrase-file root.pass
# or: --passphrase PROMPT
# or: --passphrase NONE
# or: --passphrase-file AUTO
pki --dir ./pki --verbose --json create-cert --do-it --root \
  --name service --common-name service.example --organization Example \
  --san service.example --passphrase-file leaf.pass --issuer-passphrase-file root.pass
```

Verbose reports never include raw OpenSSL stdout or stderr. Password values and sources (`-pass`, `-passin`, `-passout`, `pass:`, `file:`, `fd:`, `env:`), `/proc/self/fd/*`, private-key/passphrase paths, temporary staging paths, recovery paths, and absolute PKI paths are redacted. Supplied passphrase filenames and contents are never reported. Root dry runs include sanitized planned commands and planned relative artifact paths in normal human output and JSON output.

For create operations, `artifacts.planned` lists final `--dir`-relative files in a dry run. A successful execution lists final files in `artifacts.published` only after atomic publication; it does not claim staged files were created. `artifacts.created` is reserved for future separately-created final artifacts and is empty for the current atomic workflow. Generated CA passphrases may appear as a final relative artifact path, never as a value.

## JSON output

Use either form:

```sh
pki --dir ./pki --json check
pki --dir ./pki --output json check
```

A successful report contains fields such as:

```json
{
  "schema_version": 1,
  "ok": true,
  "code": 0,
  "dry_run": true,
  "paths": [],
  "commands": []
}
```

Non-verbose JSON remains a single document with schema version `1` and preserves the established fields. Verbose JSON additively includes `commands[].context` (`operation`, `phase`, `issuer`, and `parent` where applicable), `commands[].launch_error` when process launch failed, and `artifacts` with `planned`, `created`, and `published` arrays of `--dir`-relative `{ "path": ... }` objects. Each command always retains sanitized `argv`, `status` (`success`, `code`, `signal`), and `stdout_bytes`/`stderr_bytes`; raw OpenSSL output is never serialized. When a CA passphrase is generated, the additive `passphrase_source: "generated"` and `generated_passphrase_path` fields identify only the final relative artifact. Supplied passphrase paths are never reported.

Parser failures also use JSON when `--json` or `--output json` is present. Help and version output retain normal Clap formatting.

## Recovery after rollback failure

If rollback cannot restore an issuer database, the command exits `12` and atomically publishes an owner-only `.recovery-<transaction-id>` directory inside that issuer’s `ca` directory.

If a child artifact was published but parent durability, transaction commit, or lock release reported a failure, the tool publishes `.reconciliation-<transaction-id>` instead.

A completed record contains `manifest.json` with:

- `schema_version: 2`.
- `completed: true`.
- Record type and transaction ID.
- Target path relative to `--dir`.
- Sanitized failure information.
- Database and `newcerts` inventory with modes and lengths.

Recovery records contain database state and public `newcerts` artifacts, never private keys or passphrases. Record directories use `0700`; record and database files use `0600`.

Recovery procedure:

1. Stop issuing certificates for the affected CA.
2. Locate the `.recovery-*` or `.reconciliation-*` record.
3. Confirm `manifest.json` has `schema_version: 2` and `completed: true`.
4. Verify the listed lengths and modes.
5. Restore only listed database files and approved `newcerts/<hex-serial>.pem` files.
6. Do not remove unrelated files.
7. Verify the CA database and certificate chains with OpenSSL.
8. For reconciliation records, do not delete the published target before verification.
9. Delete the record only after recovery is complete.

`.stage-*` directories are private work directories, not recovery records.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Success |
| 2 | CLI parsing or argument failure |
| 3 | Unsafe path or layout |
| 4 | Missing or invalid required input |
| 5 | Existing target or collision |
| 6 | Filesystem failure |
| 7 | Lock or concurrency failure |
| 8 | OpenSSL unavailable or launch failure |
| 9 | OpenSSL capability/version failure |
| 10 | OpenSSL command failure |
| 11 | Certificate or artifact validation failure |
| 12 | Rollback, recovery, cleanup, or reconciliation failure |
| 13 | Configuration failure |
| 14 | Internal application failure |
| 15 | Unsupported platform or capability |

## Docker troubleshooting

### Permission denied on `/data/pki`

The runtime uses UID/GID `10001:10001`:

```sh
sudo chown -R 10001:10001 ./pki
chmod 700 ./pki
```

### Passphrase file rejected

Check ownership and mode:

```sh
stat ./pki/root.pass
sudo chown 10001:10001 ./pki/root.pass
chmod 600 ./pki/root.pass
```

### OpenSSL unavailable

The runtime image includes OpenSSL:

```sh
docker run --rm \
  --entrypoint /bin/sh \
  gywadmin-pki:local \
  -c 'command -v openssl && openssl version'
```

### Need a shell inside the runtime image

The image entrypoint is `pki`, so override it:

```sh
docker run --rm \
  --entrypoint /bin/sh \
  gywadmin-pki:local
```

## Docker lifecycle validation

The builder stage runs the Rust quality gates, and the runtime stage verifies `pki --help`, OpenSSL, and runtime shared libraries. For a complete final-image lifecycle test:

```sh
work=$(mktemp -d)
chmod 700 "$work"
printf 'root-secret\n' > "$work/root.pass"
printf 'leaf-secret\n' > "$work/leaf.pass"
chmod 600 "$work"/*.pass
sudo chown -R 10001:10001 "$work"

docker run --rm \
  --mount "type=bind,src=$work,dst=/data/pki" \
  gywadmin-pki:local \
  --dir /data/pki \
  create-ca --do-it \
  --profile ed25519 \
   --name example-root \
   --common-name "Example Root" \
   --organization Example \
   --passphrase-file root.pass
# or: --passphrase PROMPT
# or: --passphrase NONE
# or: --passphrase-file AUTO

docker run --rm \
  --mount "type=bind,src=$work,dst=/data/pki" \
  gywadmin-pki:local \
  --dir /data/pki \
  create-cert --do-it \
  --root \
  --profile ed25519 \
  --name service \
  --common-name service.example \
  --organization Example \
  --san service.example \
  --san 127.0.0.1 \
  --passphrase-file leaf.pass \
  --issuer-passphrase-file root.pass

rm -rf "$work"
```

## Certificate key usage

Certificate-producing commands accept repeatable typed `--key-usage` values. CA defaults are `key-cert-sign,crl-sign`; leaf defaults are `digital-signature,key-encipherment`.
