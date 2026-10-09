# 16 — Observation Harness

## Why

Catalog entries must describe what an anti-cheat *actually* installs, on a real
machine, at a real version. Not what a forum post from 2023 said, not what
another tool's source code implies, and not what anyone remembers.

Wrong catalog data deletes the wrong thing on someone's machine. The harness
exists so every entry is derived from an observed diff.

## Principle

```
snapshot(clean) → install → snapshot(dirty) → diff → catalog draft
              → official uninstall → snapshot(after) → diff → RESIDUE
```

The second diff is the more valuable one. It is the exact set of things the
vendor's own uninstaller leaves behind — which is the entire reason WardSweep
exists.

## Commands

```powershell
wardsweep observe snapshot -o 01-clean.json
# install the game + anti-cheat
wardsweep observe snapshot -o 02-installed.json
# uninstall via the official uninstaller only
wardsweep observe snapshot -o 03-uninstalled.json

wardsweep observe diff --before 01-clean.json --after 02-installed.json -o footprint.json
wardsweep observe diff --before 03-uninstalled.json --after 01-clean.json -o residue.json
wardsweep observe suggest --diff footprint.json --residue residue.json -o draft.toml

# a diff written by an older build: apply the current privacy rules and diff
# format to it
wardsweep observe refilter --in footprint.json -o footprint.json
```

`suggest` emits a **draft** catalog entry. It is a starting point requiring
human review, never a finished entry — see "Review before submitting" below.

## What a snapshot captures

| Domain | Captured |
|---|---|
| Services | Full `QueryServiceConfigW` + `QueryServiceConfig2W` for every service and driver |
| Registry | `HKLM\SOFTWARE` (both WOW64 views), `HKLM\SYSTEM\CurrentControlSet\Services`, `Run` keys, uninstall keys, `HKCU\SOFTWARE`; values, and keys left standing with none |
| Filesystem | Path, size, SHA-256, mtime, Authenticode signer for `%ProgramFiles*%`, `%ProgramData%`, `%LOCALAPPDATA%`, `%APPDATA%`, `System32\drivers`, launcher libraries |
| Scheduled tasks | Full XML export of every task |
| Firewall | Every rule via `INetFwPolicy2` |
| Event log sources | Registered sources under `EventLog\Application` |
| Environment | Windows build, locale, installed launchers and versions |

Alongside the domains, every snapshot records **when each domain started**, the
**boot session** it belongs to, and the **directories and registry keys with
nothing beneath them**. They exist for the same reason and are covered below: a
file list and a service list, on their own, answered three questions wrongly on
a real machine, and a list of registry values had the same blind spot as the
file list.

Snapshots are **read-only**. The harness has no removal code path at all — it
ships as `wardsweep-observe.exe`, built from `tools/observe/`, for exactly
this reason. `wardsweep observe …` in [`11`](11-CLI-REFERENCE.md) forwards to
it rather than linking its logic into the broker frontend. Releases carry it as
a download of its own, for the reason in
[`14`](14-DISTRIBUTION-TRUST.md); extracted beside `wardsweep.exe`, it is what
`wardsweep observe` runs.

Size and time, measured rather than estimated. On the development machine —
551 000 files under those roots, of which 90 000 are hashed — a full format 2
snapshot is **196 MB uncompressed** and takes **between three and a half and
ten minutes**, with hashing and the signer lookup running in parallel. The walk
reads about 100 GB, 54 GB to hash and 48 GB again to check signatures, so it is
bound by the disk rather than the processor: one build measured both ends of
that range on the same day, and at the slow end the disk sat at about 135 MB/s
with a queue 28 deep while the harness used a fifth of one core. The earlier
estimate of 40–120 MB was optimistic for a machine with games and toolchains
installed.

It also needs memory: the walk holds every record before serialising, and
resident set was observed at **around 550 MB** part-way through a capture on
that machine. That is a harness number, not a product one — `docs/10` budgets
the broker, which streams — but anyone running `observe` on a small machine
should know it before starting.

The resulting diff is small: **0.1 MB and under three seconds**, because
almost nothing changes between two snapshots. That asymmetry is the design
working — the snapshot is machine input and is written compact, the diff is
what a person reads and is written indented.

Committed diffs, not committed snapshots.

### Snapshots taken under different policies are not comparable

A snapshot records the roots it walked, the fragments it excluded, and the hash
policy it applied. `diff` compares them and **says so loudly when they differ**,
because changing the exclusion list moves files in and out of the snapshot
without anything happening on the machine.

This is not hypothetical. Two development snapshots taken either side of one
exclusion-list change produced 109 differences, of which 86 were the list. A
later pair, across a second change, produced 31 579. A diff that cannot notice
that is a diff that invents evidence.

For contrast, the same machine under an **unchanged** policy, five minutes
apart and in use the whole time: **18 file differences**, all of them Electron
application state — a desktop app's `leveldb` and `IndexedDB` directories, and
a vendor tray application's log.

That number is the one to judge a new noise rule against. Eighteen is already
low enough that adding rules to reduce it costs more than it saves: every
exclusion is a directory that is never read again, and the `\temp\` mistake
above shows how that fails. If residual noise ever does need addressing, prefer
a *suppression* rule — which relocates a change and keeps it recoverable — over
an *exclusion*, which does not.

### Formats, and why two of them are never compared

A snapshot carries `format_version`, and **`diff` refuses two snapshots of
different formats** rather than compare them. Each format change alters what a
snapshot holds without anything on the machine changing, which is the same
failure as a policy change and a louder one. Format 2 (2026-10-08):

- records the topmost registry keys with no value beneath them, below;
- records a value larger than 4 KB by name, type and size instead of skipping
  it — never its data, and never a digest, since a hash of a blob that holds an
  identifier is a fingerprint;
- walks `HKLM\SOFTWARE\WOW6432Node` once. The 64-bit walk used to descend into
  it as well, so every 32-bit key was recorded twice under two names; it is now
  left to the 32-bit walk, which reads the same keys under their own names;
- names service types for what the flags mean: `0x40` and `0x80` are
  `user_service` and `user_service_instance`, combined with the process bits
  rather than alternatives to them, and `0x4`, `0x8` and `0x200` have names now,
  so a file system recognizer counts as a driver;
- excludes `%LOCALAPPDATA%\Packages` by its full name. The bare `\packages\`
  fragment it replaces also excluded every other directory called `Packages` —
  including a game's own.

Across any one of those, every per-user service would read as modified and
every 32-bit key as removed. A format 1 snapshot is still read, and two of them
still compare.

Diffs have a format too. Diff format 2 adds `emptied_keys`, says which snapshot
format it came from in `snapshot_format_version`, and records a modified
registry key with **only the values that changed** — format 1 carried both
records whole, which is how a whole activity store once reached a committed
file through one changed value. `refilter` brings an older diff to the current
format; it cannot add what the snapshots never recorded, and
`snapshot_format_version` keeps saying so.

### A snapshot is not an instant

The services are enumerated, then the filesystem is walked, then the registry.
On a developer machine the skew between the first and last domain is around
**five minutes**, so a value that changes during the walk is captured
inconsistently *across domains, within one file*.

Measured: a Riot Vanguard baseline recorded `vgk start_type = system` in the
services domain and `Start = 3` (demand) on that same service's registry key
four minutes later, because the driver came up at `SYSTEM_START` after a reboot
and was lowered to `demand` about ten minutes in. Both readings were correct.
The file implied they were simultaneous.

Every snapshot therefore records `domain_started_utc` per domain and prints the
span it covered. That does not remove the skew — nothing short of a
transactional capture would, and Windows offers none across these three
domains — but it stops the file making a promise it cannot keep, and it tells a
reviewer which cross-domain comparisons are safe.

### A snapshot records which boot it belongs to

A restart changes more than anything else a diff will see: drivers load and
unload, per-user service instances are recreated with fresh suffixes, and
`PendingFileRenameOperations` is executed and cleared. None of that is visible
as a restart in the diff — it is visible as churn, and a reviewer attributes
churn to whatever the observation was about.

That is not hypothetical either. The Vanguard start-type finding above was
first written down with the wrong cause, because the machine had restarted
between two snapshots and neither file said so.

`boot_session` is therefore recorded on every snapshot, derived as wall clock
minus `GetTickCount64`, and `diff` reports `rebooted_between`. Both halves of
that subtraction drift, so two boot instants are compared with a **two-minute
tolerance** rather than for equality.

Measured: across two captures seven minutes apart the derived instants differed
by **7 ms**, and the one derived from `GetTickCount64` matched the boot time in
the Windows event log **to the second**. The tolerance is not sized for that
drift; it is sized for a clock step such as a time sync. It cannot hide a
restart, because a reboot moves the boot instant forward by the machine's
uptime at that moment — which had to cover the whole of the earlier capture, so
it is always minutes.

This is not a Safety Gate G3 concern. A boot instant changes every time the
machine starts and is shared by every machine started at the same moment, so it
distinguishes nothing. G3 is about identity; this is state.

### A directory that survives with nothing in it

`files` describes files, so a directory left standing and empty produces no
record on either side of a diff, and the diff cannot mention it.

Measured: Riot Vanguard's uninstaller removed all twelve of its files, both
services and every one of its registry keys, and left
`C:\Program Files\Riot Vanguard` and its `Logs` subdirectory on disk. **The
clearest residue on the machine was the one thing the harness was structurally
unable to report.**

`file_empty_directories` records directories holding no file anywhere beneath
them, topmost only — an empty `Logs` inside an empty `Riot Vanguard` is one
finding, not two — and `diff` reports `emptied_directories`.

Measured, because a list this long has to justify itself: **18 216** such
directories exist on the development machine, costing 2.46 MB, or **0.93 % of a
snapshot**. 84 % of them are one tool's metadata cache. And the noise floor is
**zero** — two captures seven minutes apart on a machine in ordinary use
produced 0 newly empty and 0 newly occupied, in both directions. So no
suppression rule is needed here, and none has been added. If one ever is, it
belongs in the noise filter where it can be named and audited, not in the
exclusion list where the directory would never be walked at all.

### A key that survives with nothing in it

The registry has the same shape. A record is written only for a key holding a
value, so a key whose values were deleted while the key itself was left standing
looked, in a diff, exactly like a key that was deleted — and a key created with
no values did not appear at all.

`registry_empty_keys` records the topmost keys with no value anywhere beneath
them, each in the view it was read through, and `diff` reports `emptied_keys`.
A key the walk would not look inside — excluded, unreadable, or the
`WOW6432Node` alias — counts as holding something, because it is not known to
be empty. So does a key whose only values were refused.

Measured on the development machine: **7 072** such keys, costing 0.98 MB, or
**0.5 % of a snapshot**. Two captures eleven minutes apart on a machine in
ordinary use produced **0** newly emptied keys, against 34 changed registry keys
and 72 changed files in the same pair. So, as with directories, no suppression
rule is needed.

Both lists are compared exactly, topmost entry against topmost entry. A subtree
that was already empty is therefore reported again if a value lands beside it
and splits it in two. That errs towards saying too much, which a reviewer can
see through, rather than too little, which nobody can.

### Absence and emptiness are different answers

`boot_session`, `file_empty_directories`, `registry_empty_keys`,
`rebooted_between`, `emptied_directories` and `emptied_keys` are all optional,
and a diff answers `null` rather than `false` or `[]` when either snapshot
predates the field.

An empty list would read as *nothing was left behind*. That is the one wrong
answer this tool must never give, and it is the same rule `coverage` has
enforced since the first snapshot: a harness that could not see something says
so, and never lets silence stand in for a clean result.

## Reducing noise

A snapshot pair taken minutes apart on an idle machine still differs in
thousands of places — Windows Update, Defender definitions, browser caches,
telemetry, MRU lists, prefetch.

The differ applies a noise filter:

- Ignore list of known-volatile paths and keys (shipped, versioned, reviewable).
  Keep the fragments **precise**: an early version excluded a bare `\temp\`,
  which caught the system temp directories as intended and also every
  application that keeps its own `…\SomeGame\Temp\`. An excluded directory is
  never read, so unlike a suppressed change it cannot be recovered from the
  snapshot afterwards — the cost of a rule that is too broad is silent and
  permanent.
- Ignore `LastWriteTime`-only registry changes with unchanged values
- Ignore files under `%TEMP%`, `%SystemRoot%\SoftwareDistribution`, Defender
  platform directories, browser profiles
- Collapse per-file changes under a single new directory into one entry
- Group by Authenticode signer, so vendor-signed additions cluster together

**Signer clustering is the single most useful signal.** Everything the anti-cheat
installer dropped shares a publisher, and it separates instantly from Windows
Update noise.

To reduce noise further, before snapshotting:

```powershell
Stop-Service wuauserv
Set-MpPreference -SignatureScheduleDay Never    # test machine only
# close browsers and launchers
```

Take snapshots at a consistent point: freshly booted, idle for two minutes, all
launchers closed.

### Safety Gate G3 constrains what the registry walk may record

`docs/02-SAFETY-GATE.md` G3 forbids reading a hardware identifier **including
for reporting**, and a walk of `HKLM\SOFTWARE` passes straight through
`Microsoft\Cryptography` on its way.

Excluding that key was the obvious first answer and is nowhere near sufficient.
Measured on a development machine, the machine identifier had been copied by
three unrelated applications into their own keys — a Visual Studio installation
key, a developer-tools hardware cache, and a cloud-storage client — all holding
the same value. A separate telemetry cache held the motherboard and CPU model
inside a URL query string, under a value whose name gave no clue. One of those
keys also held a disk serial.

So the refusal matches on the **value name and the value data**, not only on the
key path. The term list is shipped as data
(`tools/observe/src/collect/g3-identity-terms.txt`), refused values are dropped
entirely rather than masked, and each refusal is recorded in `access_denied`
with its key and value name — never its data — so the refusal is auditable.

On that machine the result is 54 values refused out of 217 522 keys, and no
hardware identifier anywhere in the snapshot.

One narrowing is worth knowing about, because it looks like a loophole and is
not: a value whose data begins with `prop:` is a Windows shell *property
schema* — it names properties, it does not hold one — and the data check skips
it. Without that, 184 of 243 refusals were schema lists. The name check still
applies to them.

Reading what the walk actually reaches turned up four more, all now excluded by
key: TPM state under `Services\TPM`, paired Bluetooth devices keyed by MAC
address under `BTHPORT\Parameters`, `MountPoints2` keyed by volume GUID, and
network signatures holding the default gateway's MAC address. The DHCPv6 unique
identifier under `Services\Tcpip6\Parameters` embeds a MAC address under a name
no MAC-address term matches, so the term list names it directly.

### Personal identity and activity history are not recorded either

Diffs are committed to a public repository, and two of them carried the
contributor's Microsoft-account e-mail address — as the *name* of a key under
`IdentityCRL` — along with the account's identifiers, the machine's host name
and OneDrive's record of host and user names. `redact` caught none of it. They
also carried the contributor's activity history: Program Compatibility
Assistant's list of every program run, `FeatureUsage`, `TypedPaths`, jump lists
and open-window records, all of which churn between any two snapshots and so
reach every diff.

None of that is footprint an installer wrote, so the walk no longer reads it:
the account cache, OneDrive's keys, Office's user name, network names, the
activity stores above and the background-activity timestamps under
`Services\bam`. Values named `HostName`, `NV HostName`, `ComputerName`,
`RegisteredOwner`, `RegisteredOrganization` and `UserEmail` are refused wherever
they appear. The rules live in one place, `tools/observe/src/policy.rs`.

The third observation, EA's anti-cheat on 2026-10-09, found more of the same
kind in an ordinary install diff, and the walk no longer reads it either: the
Microsoft account's authentication cookies, the sync store that lists which
applications and which Steam games the account has used, the keyed hashes a
Chromium browser keeps over its preferences, and telemetry state. And `redact`
now masks the data of any value whose name ends in `SessionId`, `DeviceId`,
`MachineId`, `ClientId`, `InstallId`, `UserId` or `AccountId` as `%ID%`, keeping
the name: EA's anti-cheat stores two session identifiers under its own key,
and the key and the names are footprint while the identifiers mean something
only to the vendor.

The same diff showed the filesystem's share, and the walk leaves that out too:
Windows Timeline's activity store, recent items and jump lists, crash reports
named after the programs that crashed, the Microsoft account's sign-in records
and token cache, and OneDrive's folder; the Steam client's per-account data,
caches and download manifests, which carry the Steam account's identifier in
folder and file names and between them list every game it owns; EA's cache of
account avatars, named after the accounts' identifiers; and the Claude desktop
app's session state. Steam's per-application state under
`HKCU\SOFTWARE\Valve\Steam\Apps` is the registry side of the same list and
is excluded. The machine-wide key of the same shape under `HKLM` is not, because
it is footprint: Steam's record of which steps of a game's install script have
run, and the step that installs EA's anti-cheat is one of them. Values named
`AutoLoginUser`, `ActiveUser` and `LastGameNameUsed` — Steam's remembered
sign-in name, the signed-in account's identifier and a persona name — are
refused wherever they appear. The directories are listed beside the walk, in
`tools/observe/src/collect/filesystem.rs`.

It showed more of the registry's activity history as well, now excluded: which
programs used the camera, microphone or screen capture and when, each
application's notification counts, the last program to run full screen and the
last to open a game controller — another game, in this diff — Windows Backup's
lists of installed applications and pinned tiles, Start's rotating record of
recently added shortcuts, whose slot still named the game that held it before,
the display strings Explorer resolved, the files each Store application keeps
lasting access to, and Windows' cache of signed-in identities. The walk also leaves out
Windows' licensing state, which keeps the product key in plain text: on this
machine the edition's published generic key, on one activated by a retail or
OEM key the key itself.

Some identifiers belong to no store a rule can name: an account number in a
game's own file name, a launcher's folder named after a hash. Finding those is
the review's job, and `redact --also-id <TEXT>` masks each one as `%ID%`
wherever it stands on its own.

Two consequences:

- **The differ applies the rules to both snapshots before comparing them** —
  the registry policy and the walk's directory exclusions alike — so a snapshot
  taken by an older build cannot carry what the current build refuses into a
  new diff. What was removed is counted in the diff's `refiltered` field and
  printed, never dropped silently. `observe refilter` applies the same rules to
  a diff that already exists, and keeps a change it has nothing to remove from
  exactly as written: an identifier `redact` masked on both sides reads as
  unchanged, and recomputing the change would lose it.
- **One class of evidence is now out of view by design.** An observation once
  found that the harness itself had left the anti-cheat's directory in
  Explorer's `TypedPaths`, which a name-matching residue scanner would have
  attributed to the anti-cheat. The harness can no longer see that; the note
  that recorded it stands.

## Draft entry generation

`observe suggest` produces:

```toml
# DRAFT — generated from footprint.json 2026-08-12
# Windows 11 26100.xxxx · Game vX.Y · Launcher vZ
# REVIEW EVERY FIELD BEFORE SUBMITTING

[[anticheat]]
id      = "REVIEW-me"
display = "REVIEW: from signer CN"
kind    = "kernel"          # inferred: a driver service was created
shared  = true              # DEFAULT — prove otherwise before changing
risk    = "critical"        # inferred: SERVICE_BOOT_START observed

authenticode_cn = ["<observed signer CN>"]
services = [ ... ]
drivers  = [ ... ]
paths    = [ ... ]
registry = [ ... ]
```

Inference rules, all deliberately conservative:

| Observation | Inferred |
|---|---|
| Driver service created | `kind = "kernel"` |
| `SERVICE_BOOT_START` | `risk = "critical"` |
| No driver, only a user-mode service or process | `kind = "usermode"` |
| Anything unknown | The most conservative value |

`shared` always defaults to `true`. It is downgraded only with positive evidence
across multiple observed titles — a wrong `shared = false` is the G1 failure
mode.

The table applies to what can be **attributed** to the publisher, and services
and drivers are attributed before anything else, because an attributed service's
image and name become evidence for paths and keys. A service or `.sys` file
counts when the publisher signed it, when it sits in the same folder as a file
the publisher signed, when it carries the same file name as one of them, or when
its name is one of the product folders they live in. Anything added between the
two snapshots that meets none of those — a driver Windows Update dropped, a
second program installed at the same time — is left out of the draft and
**named** in its review notes, one note each, so a reviewer can put back what is
genuinely the anti-cheat's. Names are matched as whole words, so a three-letter
service name does not claim every path that happens to contain it.

A third observation, EA's anti-cheat beside the EA app, refined that in four
places:

- **Only product folders identify anything.** The identifiers come from the
  first two folders below a root — `Program Files\<vendor>\<product>`,
  `%LOCALAPPDATA%\<product>` — not from every folder a signed file sits in. The
  EA app keeps its plug-ins in folders called `settings` and `universal`, and
  those used to claim `Local Settings` and the speech platform's keys. An
  installer's `SOFTWARE\<vendor>\<product>` key is claimed by the product folder
  it mirrors.
- **A file beside a signed one is attributed.** EA's service binary is 190 MB,
  past the size above which the walk reads no signature, so nothing signed sat at
  the service's image — only next to it.
- **A driver known only to the registry is found.** A `Services` key of a
  kernel, file-system or recognizer driver that the service control manager did
  not list is counted for `kind`, put in `services` and `drivers` when it can be
  attributed — by its key, its image, or a description that names the publisher
  — and named in the review notes either way.
- **`--only` narrows a draft to one product.** A publisher that signs its
  launcher as well as its anti-cheat gets both from a signature; the draft says
  so, naming the product folders, and `--only eaanticheat --only "ea\ac"` keeps
  only what mentions one of those texts. It narrows; it never attributes on its
  own.

Event log sources the footprint registered are put in `event_sources` when
their name carries one of the anti-cheat's identifiers or the publisher's name,
and named in the review notes otherwise. A source's key says little about its
owner — EA's names Windows' generic `EventCreate.exe` as its message file.

When an entry's key absorbs keys below it, it takes their WOW64 views too: EA
writes `EA\AC` through the 64-bit view and `EA\AC\Installs\fc26` through the
32-bit one, and an entry claiming only the first would miss the second.

## Review before submitting

The generated draft is a hypothesis. Before it becomes a catalog entry:

- [ ] Verify every signer CN with `signtool verify /v /pa <file>` and paste the
      output into the PR
- [ ] Confirm each path is genuinely anti-cheat, not a shared vendor directory
      that other software also uses
- [ ] Classify each path: `install` / `data` / `config` / `cache` / `log`
- [ ] Separate save paths into the game's `saves` list — check both
      `%LOCALAPPDATA%` and `Documents`
- [ ] Confirm `shared` against at least two titles, or leave it `true`
- [ ] Test the `official_uninstall` command manually and record what it does
- [ ] Cross-check the residue diff: what did the official uninstaller leave?
- [ ] Read the diff for identifiers no rule knows — account numbers and hashes
      in file and folder names — and mask each with `redact --also-id`
- [ ] Attach the diff JSON to the PR

## Multi-title observation

For a shared anti-cheat, repeat across at least three titles from different
launchers. The intersection of the three footprints is the anti-cheat itself;
the differences are per-title integration.

```powershell
wardsweep observe intersect --diff a.json --diff b.json --diff c.json -o shared.json
wardsweep observe suggest --diff shared.json -o draft.toml
```

This is how a `shared = true` entry gets its footprint right, and it directly
feeds spike S2.

The result is a diff like any other, so `suggest` drafts from it, and it says
it is an intersection: `intersection_of` lists each footprint by its two
snapshot times and its change count — never by file name, which is whatever the
contributor called it under whatever profile they keep it. The rules:

- **Matched by identity, never by content.** A service matches by name, a file
  by path and a registry key by path and view, ignoring case. Two titles
  routinely ship different builds of one anti-cheat, so matching on hash or
  image path would find nothing shared at all. The record kept is the first
  footprint's.
- **A change kept anywhere stays kept.** The noise filter is not recorded in a
  diff, so footprints made with different filters can disagree about a change;
  it is shown as suppressed only if every footprint suppressed it.
- **Coverage is what every footprint covered.** A domain one footprint never
  captured cannot be shown to be shared, and is reported as not captured rather
  than as empty. `emptied_directories` and `emptied_keys` follow the same rule.
- **Refused material never passes through.** Each footprint is brought under the
  current privacy policy first, and `refiltered` sums what was removed from
  each.
- **Refused outright:** fewer than two footprints, the same footprint twice
  (one title counted as two), a footprint that is itself an intersection, and
  footprints whose snapshots differ in format.

A title observed with the anti-cheat **already installed** has it missing from
its footprint, and then so does the intersection. That errs towards too little
— a shared footprint without the anti-cheat's own service is conspicuous — but
it means every title's "before" snapshot has to be genuinely clean.

## The uninstall-and-reinstall cycle

Games already installed before the harness existed have no clean "before"
state. Recovering it:

1. `wardsweep observe snapshot -o 00-current.json`
2. Uninstall via the **official uninstaller only** — do not use WardSweep
3. `wardsweep observe snapshot -o 01-clean.json`
4. Diff `01-clean` against `00-current` → this is the **residue** the vendor
   left, which is directly valuable
5. Reinstall
6. `wardsweep observe snapshot -o 02-installed.json`
7. Diff → the true footprint

Step 4 alone justifies the cycle. It answers "what does the official uninstaller
miss?" with evidence, which is the founding claim of the whole project.

Until the reinstall half exists, the uninstall half can still be drafted from: a
diff taken from `00-current` to `01-clean` holds what the uninstaller removed as
*removals*, and `suggest --removed` reads it the other way round so that they
are the footprint. What the uninstaller left behind is in neither snapshot's
difference, so it is not in that draft either.

## Storage

```
observations/
├── 2026-08-12-example-shooter-steam/
│   ├── meta.json            machine, versions, dates
│   ├── footprint.json       install diff
│   ├── residue.json         post-uninstall diff
│   ├── draft.toml           generated entry
│   └── notes.md             anything the tooling could not capture
```

Diffs are committed. Raw snapshots are not — they contain full path listings of
a real machine and are large. If a raw snapshot must be shared for debugging,
run it through `wardsweep observe redact` first, which replaces usernames and
per-user paths with placeholders.

`redact` removes **identity, not secrets**, and says so. Rewriting
`\Users\name\` is not sufficient: on a development machine that left 213
occurrences of the account name behind, in file names and registry keys that
applications had written it into — `…\User Account Pictures\name.dat`,
`…\ConnectedDevicesPlatform\L.name.cdp`. So it learns the account names from
paths **rooted at a drive letter** and replaces them wherever else they appear.

Two consequences worth knowing:

- Names are learned only from a rooted profile path. Learning from any
  `\Users\` segment taught it that `desktop.ini`, `guest` and `*` were people
  — from a container layer, an Android source tree and an ASP.NET sample — and
  it then replaced those tokens across the whole document.
- Replacement is on token boundaries, so an account name inside a longer word
  survives. `redact` counts what remains — in any letter case, in values and in
  object keys — prints the first few occurrences in context with the name
  masked, and exits non-zero. It does not claim to have produced a clean file,
  and `docs/16`'s checklist still expects a person to read one before it is
  attached to anything.

Three more rules came from a committed diff that carried an e-mail address with
the account name glued to digits in front of the `@`, which the boundary rule
cannot reach and the old report described as "`Anonymous` and the like":

- E-mail addresses are replaced with `%EMAIL%` wherever they appear, before any
  name is.
- Names are matched in any letter case. Windows account names are
  case-insensitive and applications write them however they like.
- The local machine's computer and account names are removed too, because a
  document has no reliable path to learn them from; `--also-name` adds another,
  for a file that has been redacted once already and so teaches nothing.

A fourth came from the EA AntiCheat install diff, which carried the account name
72 times inside registry binaries: shell links in a Store application's storage
table, written as hex. No text rule could see them, and the report said no name
remained.

- **A value written as hex is decoded and searched too**, for each name as
  ASCII and as UTF-16. A name found there is replaced by its placeholder in the
  same encoding, on the same token boundaries as text, and what is left is
  counted with the rest. The storage table itself is no longer walked.
