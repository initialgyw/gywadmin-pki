# gywadmin-pki

This is a rust project to manage my offline PKI. It is a openssl wrapper for me to manage my offline PKI so I can easily create root CAs, intermediate CAs, and certificates.

## Requirements

* Use std::process::Command to invoke the openssl CLI binary. Explicitly process stdout, stderr, and ExitStatus for every executed command.
* Use struct and Enum for state/variants
* Derive standard traits across all data structures: #[derive(Debug, Clone, Serialize, Deserialize)] (using serde for serialization)
* CLI exit code should be 0 on success, non-zero on failure. Different failures should have different exit codes.
* Write in latest version of rust
* Use type hints for all function parameters and return values and variables
* Use rustdoc for all functions, Explicitly include # Arguments, # Returns, and # Errors sections for all functions.
* Write it in a way a junior developer could understand, lots of comments. If a function is doing some dataprocess, comment on what the data looks like and what the output looks like.
** Include inline comments explaining Rust-specific concepts where used (such as ownership transfers, borrowing &str vs. String, or explicit error propagation using ?).
** Add step-by-step structural comments before data transformation code block showing expected input structures and resulting output shapes.
* -v for verbose output
* --do-it to actually execute the command

## Commands

### global

./pki --dir <offline pki directory, e.g. /Volumes/gywadmin-homelab/pki>

### Create CA

./pki create-ca

Use `--parent <selector>` with `create-ca` to create an intermediate CA. Omit `--parent` to create a root CA.

### Create Certificate

./pki create-cert --root

## Notes

Take a look at /Volumes/gywadmin-homelab/pki. Take a look at the directory structure and files. When create certs, files must be saved in that structure. Create a tmp directory --dir if you need it to test cert creation before saving to the offline pki directory.
