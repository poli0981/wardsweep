//! Wire format from `docs/08-IPC-PROTOCOL.md`, plus the one amendment this
//! spike proposes.
//!
//! Framing is exactly as specified:
//!
//! ```text
//! ┌────────────┬─────────────────────┐
//! │ u32 LE len │ UTF-8 JSON payload  │
//! └────────────┴─────────────────────┘
//! ```
//!
//! The amendment is [`Envelope::seq`]. `docs/08` requires that a reconnecting
//! UI resumes the event stream, but gives events no sequence number and `Hello`
//! no resume point, so the reconnecting client cannot say where it got to and
//! the broker cannot know what to replay. Without it the requirement is
//! unimplementable rather than merely unimplemented.

use serde::{Deserialize, Serialize};

/// `docs/08-IPC-PROTOCOL.md`: "Max frame 16 MiB."
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Protocol version carried in every envelope.
pub const PROTOCOL_VERSION: u32 = 1;

/// One message on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Protocol version. Broker and UI must agree on the major version.
    pub v: u32,
    /// Request id. Responses echo it; events use `null`.
    #[serde(default)]
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub kind: String,
    /// Monotonic event sequence number. Absent on commands and responses.
    ///
    /// The proposed amendment to `docs/08`. See the module comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    pub payload: serde_json::Value,
}

impl Envelope {
    /// A response echoing a request id.
    pub fn response(id: Option<String>, kind: &str, payload: serde_json::Value) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id,
            kind: kind.to_owned(),
            seq: None,
            payload,
        }
    }

    /// An event. `id` is null and `seq` is set.
    pub fn event(seq: u64, kind: &str, payload: serde_json::Value) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id: None,
            kind: kind.to_owned(),
            seq: Some(seq),
            payload,
        }
    }
}

/// Why a frame could not be read.
#[derive(Debug)]
pub enum FrameError {
    /// The peer closed cleanly between frames.
    Closed,
    /// The peer vanished mid-frame, or the pipe broke.
    Broken(std::io::Error),
    /// The declared length exceeds [`MAX_FRAME`].
    TooLarge(u32),
    /// The payload was not valid UTF-8 JSON.
    Malformed(String),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "peer closed between frames"),
            Self::Broken(e) => write!(f, "pipe broken mid-frame: {e}"),
            Self::TooLarge(n) => write!(f, "frame of {n} bytes exceeds the {MAX_FRAME} byte cap"),
            Self::Malformed(m) => write!(f, "malformed frame: {m}"),
        }
    }
}

/// Serialise an envelope into a length-prefixed frame.
///
/// # Errors
/// If the envelope does not serialise, or the result exceeds [`MAX_FRAME`].
pub fn encode(envelope: &Envelope) -> Result<Vec<u8>, FrameError> {
    let json = serde_json::to_vec(envelope).map_err(|e| FrameError::Malformed(e.to_string()))?;
    let len = u32::try_from(json.len()).map_err(|_| FrameError::TooLarge(u32::MAX))?;
    if json.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut frame = Vec::with_capacity(4 + json.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&json);
    Ok(frame)
}

/// Parse a frame body that has already been read off the transport.
///
/// # Errors
/// If the body is not valid UTF-8 JSON matching [`Envelope`].
pub fn decode(body: &[u8]) -> Result<Envelope, FrameError> {
    serde_json::from_slice(body).map_err(|e| FrameError::Malformed(e.to_string()))
}

/// Validate a declared frame length before allocating for it.
///
/// Reading the length and trusting it is how a hostile peer makes the broker
/// allocate 4 GiB. `docs/12-TESTING-STRATEGY.md` names "oversized length" as a
/// fuzz target for exactly this.
///
/// # Errors
/// If the length exceeds [`MAX_FRAME`].
pub fn check_len(len: u32) -> Result<usize, FrameError> {
    let len = len as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(
            u32::try_from(len).unwrap_or(u32::MAX),
        ));
    }
    Ok(len)
}
