# Security Policy

## Reporting a vulnerability

Open a GitHub Security Advisory (private) on this repository. Do not open a
public issue for anything that could be weaponised.

Please include the WardSweep version, Windows build, and — if the issue involves
a removal operation — the job ID and the exported job report.

## Threat model

WardSweep runs an elevated broker process that deletes services, drivers,
registry keys and files. The following are treated as security bugs, not
ordinary defects:

| Class | Example |
|---|---|
| **Privilege boundary** | Unelevated caller inducing the broker to remove an arbitrary path |
| **Deny-list bypass** | Catalog entry or crafted path escaping `safety::denylist` |
| **Path confusion** | Junction/symlink traversal causing deletion outside the target |
| **Catalog integrity** | Accepting an unsigned or wrongly-signed catalog |
| **Refcount defeat** | Causing a shared anti-cheat to be removed while still referenced |
| **Quarantine escape** | Restore writing outside its manifest's recorded destinations |
| **IPC** | Any process other than the launching UI binding or impersonating the pipe |

## Hardening in place

- Named pipe uses a restrictive DACL; broker verifies the client's process image
  path and signature before accepting commands.
- Catalog is Ed25519-signed; the public key is compiled into the broker. An
  unverified catalog is refused, never "used with a warning".
- The broker exposes a fixed command set. There is no generic "delete this path"
  command — every deletion must resolve to a planned artifact ID.
- Deny-list is compiled in and is checked *after* catalog expansion, so no
  catalog entry can reach a protected location.
- All `unsafe` Rust requires a `// SAFETY:` justification and is confined to
  thin Win32 wrappers.

## Antivirus detections

WardSweep will be flagged by some engines. This is expected for software that
deletes kernel drivers and services. See
[`docs/14-DISTRIBUTION-TRUST.md`](docs/14-DISTRIBUTION-TRUST.md) for the
VirusTotal permalink policy and the false-positive reporting process.

A detection is **not** automatically a security report. If you believe a release
artifact has been tampered with — the hash does not match the one in the release
notes — that *is* a security report; please file it privately.

## Out of scope

- Requests to add anti-cheat bypass, HWID modification, or ban-evasion features.
  These are refused as a matter of project policy, not as a security judgement.
- Anti-cheat vendors' own behaviour. WardSweep does not analyse, reverse, or
  document the internals of anti-cheat products beyond the file, service and
  registry footprint required to uninstall them.
