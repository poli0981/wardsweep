//! Named-pipe server and command dispatch.
//!
//! Not implemented yet. Spike S3 passed (`spikes/S3-RESULT.md`), so the
//! split-privilege design stands, and the wire format is
//! `docs/08-IPC-PROTOCOL.md` as S3 amended it.
//!
//! The property to preserve when it is written: the command surface is
//! **closed**. There is no `DeletePath`, no `DeleteKey`, no `StopService`. The
//! UI names artifact ids from a plan the broker built and holds in memory, so a
//! compromised UI cannot express "delete `C:\Windows`" — the vocabulary does
//! not contain it.
