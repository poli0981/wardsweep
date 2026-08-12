//! Named-pipe server and command dispatch.
//!
//! Not implemented. Whether it exists at all is decided by spike S3
//! (`docs/13-P0-SPIKES.md`); the wire format is `docs/08-IPC-PROTOCOL.md`.
//!
//! The property to preserve when it is written: the command surface is
//! **closed**. There is no `DeletePath`, no `DeleteKey`, no `StopService`. The
//! UI names artifact ids from a plan the broker built and holds in memory, so a
//! compromised UI cannot express "delete `C:\Windows`" — the vocabulary does
//! not contain it.
