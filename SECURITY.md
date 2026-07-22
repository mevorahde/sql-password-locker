# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Use this repository's private vulnerability
reporting feature under the Security tab when available; otherwise contact the maintainer through
a private channel published on the maintainer's GitHub profile. Do not open a public issue with
exploit details, credentials, database contents, configuration files, or other secrets.

Include the affected version, a minimal reproduction, expected impact, and suggested mitigation
if known. Use synthetic data. Receipt and remediation timelines are not guaranteed; this is a
portfolio project and has not received a professional security audit.

## Security boundaries

- The master password is entered interactively and is not persisted by the application. Argon2id
  derives a wrapping key from it; the database contains the salt, derivation parameters, and an
  AES-256-GCM-wrapped random data-encryption key. A weak master password remains vulnerable to
  offline guessing by anyone who obtains the database.
- Credential passwords are encrypted client-side with AES-256-GCM and a fresh nonce. This
  protects confidentiality and integrity of encrypted fields, but it does not protect a running,
  unlocked process or a compromised endpoint.
- Production SQL connections require encryption and certificate verification
  (`Encrypt=Yes`, `TrustServerCertificate=No`). Operators must deploy a certificate trusted by the
  client and valid for the configured SQL Server name. The application does not offer an insecure
  bypass.
- Normalized account names, timestamps, revisions, format and KDF parameters, ciphertext sizes,
  and other relational metadata remain visible to SQL Server administrators and database readers.
  Account names are also authenticated as encryption context; they are not encrypted.
- Copy operations place plaintext passwords on the operating-system clipboard. Clearing occurs
  only after a delay and only when the clipboard still contains the value written by the
  application. Clipboard managers, remote-session tooling, malware, or other processes can retain
  or observe that value. Clearing is best-effort, not erasure.
- Python cannot guarantee memory zeroization. Mutable key buffers are overwritten when sessions
  close on a best-effort basis, but immutable strings and copies held by the interpreter,
  cryptographic libraries, database drivers, GUI widgets, or the operating system may remain.

## Operations, backup, and recovery

Protect SQL Server access, backups, transaction logs, hosts, and user accounts independently of
the application's encryption. A restored or rolled-back database can reintroduce deleted
credentials, older ciphertext, metadata, or an earlier wrapped key. The application has no backup
lineage reconciliation or anti-rollback service; coordinate backups and restores at the database
and operational layers.

Only the initial schema and current format version are supported. Partial schemas, future schema
versions, altered cryptographic formats, and unsupported migrations are rejected. There is no
legacy import or automated migration path.

There is no master-password reset, master-password rotation, data-encryption-key rotation, escrow,
export, or recovery mechanism. Losing the master password makes the encrypted contents
unrecoverable. Compromise of an unlocked vault requires replacing affected credential passwords
outside this application; deleting and recreating the vault is the only built-in way to establish
new vault key material, and it does not migrate existing records.
