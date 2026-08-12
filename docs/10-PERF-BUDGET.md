# 10 — Performance Budget

## Targets

| Metric | Budget | Hard fail |
|---|---|---|
| Broker RSS, audit scan | < 40 MB peak | 80 MB |
| Broker RSS, idle after scan | < 12 MB | 25 MB |
| UI RSS, 100k findings displayed | < 120 MB | 250 MB |
| Audit scan wall time (NVMe, warm) | < 15 s | 60 s |
| Full scan with deep FS | < 90 s | 300 s |
| Catalog load + automaton build | < 50 ms | 250 ms |
| First finding streamed to UI | < 500 ms | 2 s |
| Plan rebuild on checkbox toggle | < 30 ms | 150 ms |
| Broker binary size | < 6 MB | 12 MB |

Reference machine: Windows 11, i7-14700KF, 32 GB DDR5, NVMe, with several
launchers and a realistically messy install history.

WPF's floor is roughly 55–70 MB; the 120 MB UI budget accepts that and spends
the remainder on virtualised item containers.

## Where the memory goes, and why it does not

### String arena

Naïve: `Vec<String>` of 500 000 paths averaging 80 bytes ≈ 40 MB of heap, plus
24 bytes of `String` header each ≈ 12 MB, plus allocator fragmentation.

```rust
struct Arena { buf: Vec<u8> }
#[derive(Copy, Clone)]
struct StrRef { off: u32, len: u32 }   // 8 bytes
```

Same 500 000 paths: 40 MB of contiguous bytes with **zero** per-string overhead
and no per-string allocation. Interning repeated directory prefixes cuts it
further — in practice to about 4–6 MB, because paths share long prefixes.

Each rayon worker owns an arena; arenas are concatenated at merge with offsets
rebased. No cross-thread allocator contention.

### Streaming, not materialising

The registry and filesystem trees are never fully materialised. Walkers are
iterators; findings are pushed into a bounded channel and drained by the IPC
writer. Peak memory is a function of channel depth (512) and batch size (500),
not of how much is on disk.

The UI is the backpressure valve: the broker blocks on pipe write, which stops
the walkers. A slow UI slows the scan instead of growing a queue.

### Aho–Corasick

One automaton for all patterns. `O(n + m + z)` regardless of catalog size, and
the automaton is a few hundred KB even with a large catalog. Built once, shared
by `Arc`.

The alternative — iterating patterns per path — is `O(n × p)` and turns a
catalog expansion into a performance regression. This is the single most
important algorithmic choice in the project.

### Bloom pre-filter

Before hashing or Authenticode verification, a Bloom filter over interesting
filename fragments rejects the overwhelming majority of files. 64 KB filter,
~0.1 % false positive rate, and it removes ≥ 99 % of candidates before any
syscall-heavy work.

Ordering matters: **cheap filters first.** Extension check → Bloom →
Aho–Corasick → file metadata → hash → Authenticode. Each stage is roughly an
order of magnitude more expensive than the last.

### Authenticode caching

`WinVerifyTrust` is the most expensive operation in the scan by a wide margin.
Cached by `(volume_serial, file_id, size, mtime)` for the session — file ID
rather than path, so a file seen via two paths is verified once.

## Parallelism

```rust
rayon::ThreadPoolBuilder::new()
    .num_threads(physical_cores())   // NOT logical
    .build()
```

Physical, not logical: the work is I/O and syscall bound, and SMT siblings
contend without adding throughput. On the 14700KF this is 20, not 28.

The registry walk is **single-threaded**. Registry I/O serialises in the kernel
and parallel `RegEnumKeyEx` produces contention, not speed. It is also fast
enough not to matter (~1500 service keys in a few tens of milliseconds).

## Allocator

Start with the system allocator and measure. `mimalloc` is a one-line change if
profiling shows allocator pressure — but with the arena design, allocation
counts should already be low. Do not add it speculatively.

## UI-side

- `VirtualizingStackPanel`, `VirtualizationMode=Recycling`
- Findings arrive in batches; `ObservableCollection` is updated once per batch
  on the dispatcher, never per item — per-item notification of 100k items is
  the classic WPF freeze
- Static brushes and no `Freezable` allocation inside `DataTemplate`s
- `x:Bind`-equivalent compiled bindings where WPF permits; no `PropertyPath`
  string bindings in hot templates
- Server GC disabled (`ServerGarbageCollection=false`), concurrent GC on —
  desktop workload, latency over throughput
- `TieredPGO` and `ReadyToRun` on for startup time

## Measurement

Every PR touching `scan/`, `plan/` or the UI item pipeline reports:

```
cargo bench --bench scan_corpus      # fixed synthetic corpus, committed
```

CI records peak RSS via a job wrapper and fails on hard-fail thresholds. Budgets
are enforced, not aspirational.

Benchmark corpus is a committed fixture tree (~120 k synthetic files, ~40 k
registry keys) so results are comparable across machines and over time. Real
machines are for validation, not for benchmarking — see
[`15`](15-TEST-MACHINE-PROTOCOL.md).

## Explicitly not optimised

- Report generation — runs once, at the end
- Catalog parsing — 50 ms budget is already generous
- Rollback — correctness dominates; a slow correct restore beats a fast wrong one
- Quarantine moves — same-volume rename is already instant; cross-volume copy is
  bounded by disk, not by us
