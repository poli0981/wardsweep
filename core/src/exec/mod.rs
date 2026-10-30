//! Execution pipeline, stages 0 through 6, and reboot orchestration.
//!
//! Not implemented, and deliberately so. `docs/19-ROADMAP.md` v0.1 states that
//! no removal code exists in the binary. `docs/13-P0-SPIKES.md` deferred S1,
//! S5 and S7 for v0.1 on exactly that ground, so nothing here is written
//! before they have verdicts.
//!
//! When it does arrive, `docs/06-REMOVAL-PIPELINE.md` applies: every stage is
//! idempotent, stages 0–2 are recoverable and 3 onward are quarantine-backed,
//! and nothing is deleted directly — removal means a move into
//! [`crate::quar`].
