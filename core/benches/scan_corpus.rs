//! `scan_corpus` — the benchmark `.github/workflows/rust-ci.yml` requires.
//!
//! The `bench` job runs on every push to `main` with `fail-on-regression: true`
//! and a 15 % threshold, so this target must exist and must be stable from the
//! first commit.
//!
//! There is no scanner yet, so it measures what does exist — and every group
//! maps to a real budget in `docs/10-PERF-BUDGET.md`:
//!
//! | Group | Budget it defends |
//! |---|---|
//! | `catalog_parse` | catalog load + automaton build < 50 ms, hard fail 250 ms |
//! | `automaton_build` | same |
//! | `path_canonicalise` | per-path cost, the hot path in scan and execute |
//! | `denylist_check` | same |
//!
//! The corpus is generated from a committed seed with a fixed LCG, so results
//! are comparable across machines and over time — which is what `docs/10`
//! actually asks for — without committing 120 k files. The full golden corpus
//! from `docs/12-TESTING-STRATEGY.md` arrives with the scanner.
//!
//! criterion is pinned below 0.8 on purpose: 0.8 depends on `alloca`, which
//! needs a C toolchain for the target being built. That is fine on the ubuntu
//! runner and fatal to cross-linting the workspace for Linux from a Windows
//! machine, which is the only way to reproduce the CI lint job locally.

// `criterion_group!` expands to a public item it does not document, and a bench
// binary publishes no documentation for anyone to miss.
#![allow(missing_docs)]

use aho_corasick::{AhoCorasickBuilder, MatchKind};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use wardsweep_core::catalog;
use wardsweep_core::safety::denylist::{self, Exceptions, Stage};
use wardsweep_core::safety::paths::canonicalise_syntactic;

const SEED_TEMPLATES: &str = include_str!("fixtures/paths.seed.txt");
const EXAMPLE_CATALOG: &str = include_str!("../../catalog/catalog.example.toml");

/// Size of the generated corpus. Large enough that per-path cost dominates
/// timer overhead, small enough that a run stays well under a minute.
const CORPUS_SIZE: usize = 20_000;

/// A fixed linear congruential generator.
///
/// Not for anything cryptographic — it exists so the corpus is identical on
/// every machine and in every run. `Math.random`-style nondeterminism would
/// make a 15 % regression threshold meaningless.
struct Lcg(u64);

impl Lcg {
    /// Returns an index in `0..modulus`.
    fn index(&mut self, modulus: usize) -> usize {
        // Numerical Recipes constants.
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        // Truncating to usize is deliberate and harmless: the value is only
        // used to pick a template variant.
        usize::try_from((self.0 >> 16) % modulus as u64).unwrap_or(0)
    }
}

/// Expand the committed templates into a deterministic corpus.
fn build_corpus() -> Vec<String> {
    const USERS: [&str; 4] = ["anon", "Default", "Test User", "player_01"];
    const VOLUMES: [&str; 3] = ["D", "E", "F"];

    let templates: Vec<&str> = SEED_TEMPLATES
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    assert!(!templates.is_empty(), "seed corpus is empty");

    let mut rng = Lcg(0x5EED_1234_ABCD_0001);
    let mut corpus = Vec::with_capacity(CORPUS_SIZE);
    for index in 0..CORPUS_SIZE {
        let template = templates[index % templates.len()];
        let user = USERS[rng.index(USERS.len())];
        let volume = VOLUMES[rng.index(VOLUMES.len())];
        corpus.push(
            template
                .replace("{n}", &index.to_string())
                .replace("{user}", user)
                .replace("{vol}", volume),
        );
    }
    corpus
}

/// Every pattern a catalog contributes to the detection automaton.
fn catalog_patterns(catalog: &catalog::Catalog) -> Vec<String> {
    let mut patterns = Vec::new();
    for ac in &catalog.anticheat {
        patterns.extend(ac.services.iter().cloned());
        patterns.extend(ac.drivers.iter().cloned());
        patterns.extend(ac.paths.iter().map(|p| p.path.clone()));
        patterns.extend(ac.registry.iter().map(|r| r.key.clone()));
    }
    for game in &catalog.game {
        patterns.extend(game.install_hints.iter().map(|p| p.path.clone()));
        patterns.extend(game.residue.iter().map(|p| p.path.clone()));
    }
    patterns
}

fn bench_catalog(c: &mut Criterion) {
    let mut group = c.benchmark_group("catalog_parse");
    group.bench_function("example_catalog", |b| {
        b.iter(|| catalog::parse(black_box(EXAMPLE_CATALOG)).expect("example catalog parses"));
    });
    group.finish();

    let parsed = catalog::parse(EXAMPLE_CATALOG).expect("example catalog parses");
    let patterns = catalog_patterns(&parsed);

    let mut group = c.benchmark_group("automaton_build");
    group.throughput(Throughput::Elements(patterns.len() as u64));
    group.bench_function("aho_corasick", |b| {
        b.iter(|| {
            // Same construction as docs/05-DETECTION-ENGINE.md specifies, so
            // the measurement tracks the real thing rather than a proxy.
            AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::LeftmostLongest)
                .build(black_box(&patterns))
                .expect("automaton builds")
        });
    });
    group.finish();
}

fn bench_paths(c: &mut Criterion) {
    let corpus = build_corpus();

    let mut group = c.benchmark_group("path_canonicalise");
    group.throughput(Throughput::Elements(corpus.len() as u64));
    group.bench_function("syntactic", |b| {
        b.iter(|| {
            let mut accepted = 0usize;
            for path in &corpus {
                if canonicalise_syntactic(black_box(path)).is_ok() {
                    accepted += 1;
                }
            }
            accepted
        });
    });
    group.finish();

    // Canonicalise once so the deny-list group measures the deny-list rather
    // than measuring canonicalisation twice.
    let canonical: Vec<_> = corpus
        .iter()
        .filter_map(|path| canonicalise_syntactic(path).ok())
        .collect();
    let exceptions = Exceptions::new(["vgk.sys", "EasyAntiCheat.sys"], ["vgk", "EasyAntiCheat"]);

    let mut group = c.benchmark_group("denylist_check");
    group.throughput(Throughput::Elements(canonical.len() as u64));
    group.bench_function("check_path", |b| {
        b.iter(|| {
            let mut allowed = 0usize;
            for path in &canonical {
                if denylist::check_path(black_box(path), &exceptions, Stage::CatalogLoad).is_ok() {
                    allowed += 1;
                }
            }
            allowed
        });
    });
    group.finish();
}

criterion_group!(benches, bench_catalog, bench_paths);
criterion_main!(benches);
