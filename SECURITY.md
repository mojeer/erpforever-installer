# Security model

The public repository contains only deployment/verification code, an Ed25519 verification key, tests and documentation. Product archives are encrypted with a fresh AES-256-GCM key per release. A separately authenticated key envelope is generated per valid customer entitlement. Only a holder of an issued token can unwrap their release key. A public verification key cannot issue tokens or sign releases.

The local owner signing key, token registry and entitlement files are kept outside both source repositories. Never grant repository collaborators or customer servers access to owner state. There is no remote administrative backdoor, license telemetry, customer database access, or public license issuance endpoint.

The installer binds official download entitlement to the requested hostname and expiration. This is distribution/update control, not a claim that recipients cannot inspect, modify or redistribute received GPL code. A server's root user has control over its installed software.

The web application accepts only `status`, `check`, and `apply` operations on a local Unix socket, requires the System Manager role and POST for these operations, and never submits arbitrary commands, paths or URLs. The host agent is privileged because it deploys Docker services; the socket is restricted to its service group. Backend containers have the required supplementary group. There is no externally listening update port.

Signed sequence numbers prevent rollback to older product releases. Signed image digests prevent mutable-tag substitution for ERPNext/Frappe. Checksums, authenticated encryption, bounded downloads and unpacking, and path/link/device rejection protect the product archive. The owner-controlled bootstrap is trusted separately through GitHub HTTPS. Compromise of the owner's GitHub/bootstrap or signing key is outside the authenticity guarantee; protect both with strong account security and an offline key backup.

Database, Redis, proxy, ERPNext/Frappe and addon images are pinned by immutable digest. Infrastructure references live in the signed, self-updating deployment code. The owner refreshes and validates them as part of release maintenance.

Updates stop background writers and back up database/files before migrations. A pre-migration failure restores the previous code/configuration and resumes service. A migration failure leaves maintenance enabled and records recovery-needed status. An owner must inspect and, when necessary, restore the corresponding database and files together with the previous code. An automatic code rollback is not a database rollback.

Local diagnostics and token files are root-readable only. Do not share raw diagnostics without redaction. Same-server backups do not protect against disk loss; arrange and test offsite backups before production use.
