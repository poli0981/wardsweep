# EA AntiCheat (Javelin) — observation notes

The third anti-cheat observed here, and the first from a **clean baseline**:
EA AntiCheat was not on the machine when the first snapshot was taken, so
`install.json` is the install footprint as it happened, not one reconstructed
by uninstalling and reinstalling. The install half is done. The residue half —
uninstalling the game through Steam, which is meant to run the anti-cheat's own
uninstaller — is still to do.

It is also the observation that cost the tooling most: the draft generator
missed the anti-cheat's service and driver and took in the EA app (#50), and
the diff carried more personal data than the policy covered (#51, #52). Both
are fixed, and the diff here is computed by the fixed build.

## What was observed

| | |
|---|---|
| Game | EA SPORTS FC 26 on Steam, app 3405690, in a library on `D:` |
| Before | `00-current`, 2026-10-09 15:56:30Z: the game installed and not yet launched, no EA AntiCheat service, driver or directory |
| After | `01-after-fc26`, 16:37:35Z: after the game's first launch, with the game closed; same boot |
| Anti-cheat version | 1.0.15918775, from the name of the install-script step that installed it |
| Harness | both snapshots taken by a collector pinned for the cycle (SHA-256 `fdc1b7d2f192b786…`); diffed, redacted and drafted by the build that adds #52 |

The machine was in ordinary use rather than freshly booted and idle, contrary
to `docs/16` §"Reducing noise".

## How it got there: Steam's install script

FC 26 ships `EAJavelinInstaller_installscript.vdf` beside the game. Steam runs
its steps at the game's first launch:

- **Install.** A step named `EAAntiCheatInstaller 1.0.15918775` runs
  `%INSTALLDIR%\EAAntiCheat.Installer.exe --noui --install --read-cfg`.
- **Uninstall.** A step runs the same program with `--noui --uninstall
  --read-cfg --launcher-path "%INSTALLDIR%\EAAntiCheat.GameServiceLauncher.exe"`
  when Steam uninstalls the game.

Steam records a step it has run under
`HKLM\SOFTWARE\WOW6432Node\Valve\Steam\Apps\3405690`: the value
`EAAntiCheatInstaller 1.0.15918775 = 1`, beside `EADesktopSetup = 1` for the EA
app. The diff carries that key as an addition in the 32-bit view. It is game
footprint, not the anti-cheat's, and #52 keeps it in view on purpose while
leaving out the per-account state beside it under `HKCU`.

So the vendor's uninstaller is wired to the game's uninstall. Whether it runs,
and what it leaves, is what the residue half has to show.

## The footprint

| Kind | Observed |
|---|---|
| Service | `EAAntiCheatService`: own process, `demand`, `LocalSystem`, `"C:\Program Files\EA\AC\eaanticheat.gameservice.exe"`, description "EA Javelin Anticheat" |
| Driver | `EAAntiCheat`: file-system minifilter (`Type = 2`), `demand`, `system32\drivers\eaanticheat.sys`, group `FSFilter Activity Monitor`, altitude 363250, depends on `FltMgr` |
| Files | `C:\Program Files\EA\AC`: `EAAntiCheat.GameService.exe` (190,728,952 bytes), `EAAntiCheat.GameService.dll` (63,785,208), `EAAntiCheat.Installer.exe` (278,380,280), `preloader_s.dll` (46,840): 532,941,280 bytes |
| Registry | `HKLM\SOFTWARE\EA\AC`, `HKCU\SOFTWARE\EA\AC`, both service keys, all in both views |
| Event source | `Application\EA Javelin Anticheat`, message file `EventCreate.exe` |

Every file is signed *Electronic Arts, Inc.* and timestamped. The diff records
a signer for two of the four. The other two are larger than the harness's
128 MiB hashing cap, so their signatures were not checked, which is not the
same as unsigned. Checked by hand with `Get-AuthenticodeSignature`: valid.

### The driver is not in SCM, and its image is not on disk

- **SCM does not know it.** `EAAntiCheat` is a complete service key — type,
  start, error control, image, group, a minifilter instance — and the service
  control manager answers 1060, "does not exist as an installed service". It
  answered that in the boot the anti-cheat was installed in (checked
  2026-10-09, read-only). The installer wrote the key straight into the
  registry, so the snapshot's services domain does not list the driver and only
  the registry walk sees it. That is how the first draft missed it, and why
  `suggest` now looks for registry-only drivers (#50).
- **Its image does not exist.** `system32\drivers\eaanticheat.sys` was absent
  from both snapshots and is absent now, with the game closed, although the key
  names it and the walk covers `System32\drivers`.

**Inference, not observed:** the service writes the image when a game starts
and loads it through the filter manager, which reads the service key itself and
needs no SCM record. Two things would test it: the image while a game runs, and
whether SCM lists `EAAntiCheat` after a restart.

What it means for WardSweep (`docs/05`):

- Detection has to read `Services` keys as well as ask SCM.
- Removal cannot go through `DeleteService` for a key SCM does not know.
- An image path that does not exist is this driver's normal state, not
  evidence of residue.

### EA keeps a record of the games that installed it

`HKLM\SOFTWARE\EA\AC\Installs` holds `fc26 = 1`, and the 32-bit view's
`Installs\fc26` holds `EAAntiCheatInstaller = 1`. One name per game that ran the
installer, as far as one game can show. It could cross-check the refcount
WardSweep computes (`docs/04`, `shared`), never replace it. With a single title
installed, this observation cannot tell whether the uninstaller removes a game's
entry and the anti-cheat only with the last one. The residue half shows the
first; a second EA title would show the second.

### The event source is the anti-cheat's

`suggest` names `Application\EA Javelin Anticheat` in the review notes and
leaves it out, because nothing in the name matches its tokens. It belongs to the
anti-cheat: the service's own description is the same string, and the source
appeared with it.

## What else the window caught

- **The EA app was installed alongside**, version 13.805.11.6320, with its own
  service `EABackgroundService`. The same publisher signs it, so signer
  clustering cannot separate the two, and the draft is scoped with `--only`.
  The draft's review notes name what that left out.
- Steam updated another application in the library.
- The NTE launcher was downloading a game update. NTE is the next observation
  in this cycle.
- The usual updaters churned: Discord, the NVIDIA App, Proton VPN and Edge.
- The harness's own working files no longer appear, since #52.

## Privacy

The diff was computed by the build with #51 and #52, whose rules this diff
prompted. That build removed:

| Kind | Removed |
|---|---|
| Registry records | 12,306 |
| Registry values | 8 |
| File records | 77,542 |
| Unreadable items | 47 |
| Empty keys | 10 |
| Emptied directory | 1 |

What these were:
- account and sign-in stores, credentials and licensing state;
- the Steam account's data and library lists;
- activity history, crash reports, and the harness's own files;
- the storage table in which Store applications keep shell links to the files
  they may reopen.

That last one was found the hard way. An earlier pass over this diff reported
no name left, yet the account name sat 72 times inside those shell links,
written as hex, where no text rule could reach. Since #52, `redact` decodes hex
values and searches them as well, and the table is no longer walked.

`redact` masked:
- account names, 1,027 times;
- machine SIDs, 70 times;
- 38 identifiers.

Eight of the identifiers were supplied with `--also-id` after reading the diff:
- FC 26's play-time file name and its `TLM` value;
- an EA SDK persistence file name;
- EA app folder and secure-store file names made of hashes.

The `@` in ten EA app file names is a display-scale suffix, `@2x.png`, and is
left alone since #52.

## The draft

```
wardsweep-observe suggest --diff install.json --signer "Electronic Arts, Inc." \
    --only eaanticheat --only "ea\ac" --only javelin
```

- `kind = "kernel"`, `risk = "high"`.
- The two services and the driver.
- `%ProgramFiles%\EA\AC`.
- The four registry keys.

Without `--only`, the draft takes in the EA app, because the same publisher
signs both. `shared` stays `true` until a second title has been observed. A test
pins the draft to `install.json`.

## Still to do

1. **The residue half.** Uninstall FC 26 through Steam, so the install script's
   uninstall step runs. Then take a snapshot with the pinned collector and diff
   it against the snapshot before it.
2. After a restart, ask SCM about `EAAntiCheat` again.
3. In the PR that adds the catalog entry, paste `signtool verify /v /pa` for
   every binary (`docs/16` checklist).
