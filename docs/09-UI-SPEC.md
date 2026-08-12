# 09 — UI Specification

C# / .NET 10 / WPF with [WPF-UI 4.3.0](https://wpfui.lepo.co/).

## Design intent

The user is being asked to let software delete drivers from their machine. The
interface has one job before all others: **make the user feel informed, not
managed.** Nothing hidden behind "Advanced". No progress bar that finishes and
leaves you wondering what happened.

Visual language: calm, technical, factual. Not a "cleaner" aesthetic — no green
checkmarks promising the PC is now FAST, no scare-red counts of "problems
found". Findings are stated, not sold.

## Shell

`FluentWindow` + Mica backdrop, `NavigationView` in `Left` pane mode
(`LeftFluent`), collapsing to `LeftCompact` under 1000 px.

```
┌──────────────┬──────────────────────────────────────────┐
│  Scan        │                                          │
│  Findings    │            content region                │
│  Plan        │                                          │
│  Jobs        │                                          │
│  Quarantine  │                                          │
│  Catalog     │                                          │
│  ─────────   │                                          │
│  Settings    │                                          │
│  About       │                                          │
└──────────────┴──────────────────────────────────────────┘
```

Minimum window 900 × 640. `TitleBar` with the WardSweep icon; no custom chrome
beyond what WPF-UI provides.

## Screens

### Scan

Landing screen. Three cards:

| Card | Description | Elevation |
|---|---|---|
| **Audit** | Read-only. Find every anti-cheat and report. Changes nothing. | None |
| **Orphan Sweep** | Find anti-cheat with no owning game. | Required at apply |
| **Full Scan** | Games + anti-cheat + residue. | Required at apply |

Audit is visually primary. It is the recommended first action and the only one
that cannot hurt anything.

During scan: `ProgressRing`, live counter, current phase label, findings
streaming into the list beneath. Cancel is always available and immediate.

### Findings

Master–detail. `TreeView` (virtualised) on the left grouped by anti-cheat; detail
pane on the right.

```
▸ Vanguard                             [KERNEL] [BOOT-START]  ⚠ blocked
    ├ vgk.sys          C:\Windows\System32\drivers\  boot-start
    ├ vgc              service, auto
    ├ Riot Vanguard    C:\Program Files\Riot Vanguard\
    └ Referenced by:   Valorant, League of Legends
▸ Easy Anti-Cheat (EOS)                [KERNEL]              ● orphan
    └ Referenced by:   nothing installed
```

Badges: `KERNEL` / `USER-MODE`, `BOOT-START`, `SHARED`, `ORPHAN`,
`SUSPICIOUS`, `ACCESS DENIED`.

Detail pane per finding: what it is, where it lives, publisher (verified /
unverified / **mismatch**), start type, disk size, last-executed date if known,
which games reference it, and — flatly stated — what removing it would do.

An `InfoBar` (Severity `Informational`) appears at the top when the scan was
partial: *"This scan ran without administrator rights. N locations could not be
read and are not included."* This is not dismissible.

### Plan

Left: checkbox tree of games. Right: live consequence panel.

The interaction that matters: ticking or unticking a game **immediately**
recomputes refcounts and the panel updates. Untick League of Legends and
Vanguard visibly moves from *"will be removed"* to *"stays — required by League
of Legends"*.

Tier presentation:

| Tier | Presentation |
|---|---|
| `SAFE` | Ticked, collapsed |
| `REVIEW` | Unticked, **expanded**, amber `InfoBar` explaining the ambiguity |
| `PROTECTED` | Separate "Save data" section, unticked, shield glyph |
| `BLOCKED` | Greyed with a lock, and the blocking reason on the row itself |

Footer: counts, total bytes, estimated quarantine size, free space per volume.

Buttons: **Preview report** (always) · **Dry run** (default) · **Apply**
(`Danger` appearance).

### Apply confirmation

A `ContentDialog`, not a `MessageBox`. Contains:

- Plain-language summary of what happens: *"3 games uninstalled, 1 anti-cheat
  removed, 47 residue items quarantined. A restart will be required."*
- Explicit, prominent: **games cannot be restored by rollback — they must be
  reinstalled.** Everything else can be restored for 14 days.
- Restore point status (created / unavailable, with the reason)
- If any `risk = critical` artifact is involved, the user types the word
  **REMOVE** to enable the button. Once per job, not per artifact — repeated
  typed confirmations train people to type without reading.

### Jobs

History list with status chips. Selecting a job shows the stage timeline, the
per-artifact result table, and actions: **Resume** (if `pending_reboot`),
**Rollback**, **Export report**, **Open quarantine folder**.

When a job is `pending_reboot`, a persistent `InfoBar` (Severity `Warning`) sits
in the shell across every screen: *"Restart required to finish removing N
items."* with a Restart button. Never a forced reboot.

### Quarantine

Per-job cards: size, expiry countdown, entry count. Actions: restore all,
restore selected, browse in Explorer, purge now.

Global footer: total quarantine size, retention setting, purge-all.

### Catalog

Read-only browser of the loaded catalog. Signature status, catalog version,
entry count, per-entry footprint.

This screen doubles as the **Anti-Cheat Reference**: for each entry, a plain
explanation of whether it is kernel or user-mode, when it runs, and a link to
the vendor's own uninstall documentation. Scope note: it documents *footprint*,
not behaviour — see [`02-SAFETY-GATE.md`](02-SAFETY-GATE.md).

Import button for offline catalog updates. Signature status is shown before
import completes; a failed signature refuses the import outright.

### Settings

Theme (System / Light / Dark) · Language (EN / VI / JA) · Quarantine retention ·
Deep filesystem scan · Catalog update check (default **off**) · Log level ·
Open log folder · Portable mode indicator.

### About

Version, catalog version, GPL-3.0 notice, third-party notices, links to repo and
docs, **VirusTotal permalink for the installed build**, SHA-256 of the running
binaries. See [`14`](14-DISTRIBUTION-TRUST.md).

## Colour and severity

| Meaning | WPF-UI token |
|---|---|
| Informational | `SystemFillColorNeutral` |
| Review needed | `SystemFillColorCaution` |
| Blocked / critical | `SystemFillColorCritical` |
| Complete | `SystemFillColorSuccess` |

Never colour by "amount found". Twelve findings is not worse than three; it just
means twelve things exist. Severity reflects consequence, not count.

## Accessibility

- All actions keyboard reachable; visible focus in both themes
- `AutomationProperties.Name` on every icon-only control
- Contrast ≥ 4.5:1 in light, dark, and high-contrast themes
- Status never conveyed by colour alone — always badge text as well
- `TreeView` announces node state changes to screen readers

## Performance

- `VirtualizingStackPanel` with `IsVirtualizing=True`, `VirtualizationMode=Recycling`
- Findings bound to an `ObservableCollection` fed on the dispatcher in batches
  of ≤ 500, never per item
- No `Freezable` allocations in item templates; brushes are static resources
- Target: 100 000 nodes without dropping below 60 fps while scrolling

## MVVM

CommunityToolkit.Mvvm source generators, DI via `Microsoft.Extensions.Hosting`.
Broker client is an injected `IBrokerClient` with an in-memory fake for design
time and tests. **No ViewModel ever touches the filesystem or the registry** —
the UI process has no destructive code path at all.
