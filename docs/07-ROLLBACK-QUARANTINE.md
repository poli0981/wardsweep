# 07 — Quarantine & Rollback

## Principle

WardSweep does not delete. It **moves**, **exports**, and **records**. Actual
deletion happens later, on expiry, with the user able to intervene at any point.

This is the difference between a tool you can recommend and one you cannot.

## Quarantine store

```
%ProgramData%\WardSweep\quarantine\{job-id}\
├── manifest.json                   authoritative record
├── files\
│   └── C\Program Files (x86)\EasyAntiCheat\...   original tree preserved
├── registry\
│   ├── 0001_HKLM_SOFTWARE_EasyAntiCheat.reg
│   └── 0002_HKLM_SYSTEM_CCS_Services_EasyAntiCheat.reg
├── services\
│   └── EasyAntiCheat.json          full QueryServiceConfig2W snapshot
├── tasks\
│   └── EasyAntiCheat_Report.xml    exported task definition
├── firewall\
│   └── rules.json
└── saves\
    └── ExampleShooter-saves.zip    always archived, even if user opted to remove
```

Original directory structure is preserved under `files\` with the drive letter
as the first component. This makes the quarantine directly browsable — a user
can recover one file with Explorer without running WardSweep at all. That
property is worth the small path-length cost.

### Long paths

Quarantine paths can exceed `MAX_PATH`. The broker manifests
`longPathAware`, uses `\\?\` prefixed paths for all file operations, and falls
back to a hashed short name (recorded in the manifest) if a path still exceeds
32 767 characters.

### Same-volume moves

`MoveFileExW` on the same volume is a metadata rename: instant, no data copy,
no space doubling. Cross-volume falls back to copy + delete.

Quarantine therefore lives on the **same volume as the artifact**, not always on
`C:`. Multi-volume jobs create a quarantine root per volume:

```
D:\ProgramData\WardSweep\quarantine\{job-id}\
```

with the master manifest on `C:` referencing all roots. Preflight checks free
space per volume.

## Manifest schema

```jsonc
{
  "job_id": "01J8XZ...",
  "schema": 1,
  "created_utc": "2026-08-12T09:14:22Z",
  "expires_utc": "2026-08-26T09:14:22Z",
  "app_version": "0.5.0",
  "catalog_version": "2026.08.12",
  "restore_point_seq": 412,
  "roots": ["C:\\ProgramData\\WardSweep\\quarantine\\01J8XZ...", "D:\\..."],
  "entries": [
    {
      "id": "a-0001",
      "kind": "file",
      "original": "C:\\Program Files (x86)\\EasyAntiCheat\\EasyAntiCheat.exe",
      "quarantined": "files\\C\\Program Files (x86)\\EasyAntiCheat\\EasyAntiCheat.exe",
      "size": 892416,
      "sha256": "…",
      "attributes": 32,
      "acl_sddl": "O:BAG:SYD:…",
      "times": { "created": "…", "modified": "…", "accessed": "…" },
      "restored": false
    },
    {
      "id": "a-0002",
      "kind": "registry",
      "original": "HKLM\\SOFTWARE\\EasyAntiCheat",
      "view": "64",
      "export": "registry\\0001_HKLM_SOFTWARE_EasyAntiCheat.reg",
      "value_count": 14,
      "subkey_count": 3,
      "restored": false
    },
    {
      "id": "a-0003",
      "kind": "service",
      "original": "EasyAntiCheat",
      "snapshot": "services\\EasyAntiCheat.json",
      "was_boot_start": false,
      "requires_reboot_to_restore": false,
      "restored": false
    }
  ]
}
```

The manifest is written **before** the corresponding operation and updated
after. A crash between write and operation leaves a manifest entry for
something that was not moved; rollback tolerates missing sources and records
them as `already_absent`.

## Rollback

### What can be restored

| Kind | Restorable | Notes |
|---|---|---|
| File / directory | Yes | Contents, timestamps, attributes, ACLs |
| Registry key | Yes | Via `.reg` import; values and subkeys |
| Service | Yes | Recreated with `CreateServiceW` from the snapshot |
| Boot-start driver | Yes, **reboot required** to load again |
| Scheduled task | Yes | Re-registered from exported XML |
| Firewall rule | Yes | Recreated from JSON |
| Vendor uninstall (Stage 2) | **No** | Reinstall the game normally |

Stage 2 is explicitly irreversible and the UI says so, in the approval dialog,
before the user commits: *"Games are uninstalled by their official uninstaller.
Rollback restores anti-cheat components and residue, not the games themselves."*

### Order

Reverse of removal, dependencies first:

```
1. registry keys      (services need their keys)
2. files              (services need their binaries)
3. services           (CreateServiceW from snapshot, incl. SDDL & failure actions)
4. scheduled tasks
5. firewall rules
6. mark manifest entries restored:true (per entry, incrementally)
```

Per-entry commit means a rollback interrupted halfway is resumable and the
manifest always reflects reality.

### Partial rollback

The user may restore a single entry, or every entry of one kind. Common case:
"I only want my shader cache back." Supported from both UI and CLI.

### Registry restore caveat

`.reg` import is **additive**. Values created after removal are not deleted by
importing the export. This is documented in the report rather than solved —
solving it correctly would require full key replacement, which risks destroying
legitimate post-removal state. Additive restore is the safe direction.

## Expiry

- Default retention: **14 days**, configurable 1–365, or never
- A background check on broker startup purges expired jobs
- Purge is a real delete, logged, with the manifest retained for 1 more year as
  a small JSON so the job history stays meaningful after the data is gone
- Purge never runs during an active job
- The UI shows total quarantine size and a "purge now" action per job

## Testing requirements

Rollback fidelity is P0 spike **S5** ([`13`](13-P0-SPIKES.md)). The acceptance
test is a full removal on a snapshot VM followed by rollback, then a byte-level
comparison of:

- File contents (SHA-256), timestamps, attributes, ACL SDDL
- Registry key values, types, ordering, and default values
- `QueryServiceConfig2W` output for every restored service, field by field
- Scheduled task XML, normalised

Anything that cannot be restored to the byte must be documented as a known
limitation before v1.0, not discovered by a user.
