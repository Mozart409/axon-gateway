//! What a client's `tools/call` hands down to the backend call: where the
//! backend's progress notifications go and when the call is cancelled.

use rmcp::model::ProgressNotificationParam;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Progress notifications buffered per call. Progress is advisory, so when the
/// client reads slower than the backend reports, the excess is dropped.
pub const PROGRESS_BUFFER: usize = 64;

/// The client side of one forwarded tool call
#[derive(Debug, Clone)]
pub struct CallRelay {
    /// Receives the backend's progress notifications, still carrying the
    /// backend's progress token (the receiver swaps in the client's).
    /// `None` when the client asked for no progress. Senders use `try_send`.
    pub progress: Option<mpsc::Sender<ProgressNotificationParam>>,
    /// Cancelled when the client cancels its request or goes away; the
    /// backend request is then cancelled too.
    pub cancel: CancellationToken,
}
