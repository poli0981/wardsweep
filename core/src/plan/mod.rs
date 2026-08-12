//! Plan builder: artifact tree, reference-count resolver, tier classification.
//!
//! Not implemented. Arrives with v0.5 (`docs/19-ROADMAP.md`), specified in
//! `docs/06-REMOVAL-PIPELINE.md` §Stage 1.
//!
//! This is where the G1 invariant from `docs/02-SAFETY-GATE.md` is enforced:
//! for every anti-cheat in an approved plan, the set of installed games
//! referencing it must be a subset of the games being removed in the same job.
//! The invariant is checked at plan build, again at approval, and again
//! immediately before Stage 3.
