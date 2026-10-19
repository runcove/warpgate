use std::time::Duration;

use warpgate_common::{UserFacingReason, WarpgateError};

use super::ConnectionError;

#[derive(thiserror::Error, Debug)]
pub enum SshClientError {
    #[error("mpsc error")]
    MpscError,
    #[error("russh error: {0}")]
    Russh(#[from] russh::Error),
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error(transparent)]
    Warpgate(#[from] WarpgateError),
    /// The target connection did not answer a command within the bound.
    #[error("no reply from the target within {0:?}")]
    NoReply(Duration),
}

impl UserFacingReason for SshClientError {
    fn user_facing_reason(&self) -> String {
        match self {
            Self::MpscError => "Internal connection error".into(),
            Self::Russh(_) => "SSH protocol error".into(),
            Self::Connection(e) => e.user_facing_reason(),
            Self::Warpgate(e) => e.user_facing_reason(),
            Self::NoReply(_) => "The target did not respond".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use warpgate_common::{UserFacingReason, WarpgateError};

    use super::SshClientError;

    #[test]
    fn a_transparent_error_does_not_show_its_text() {
        let leaky = SshClientError::Warpgate(WarpgateError::Other(
            "database error: SELECT secret FROM credentials".into(),
        ));
        assert!(leaky.to_string().contains("SELECT"));
        assert!(!leaky.user_facing_reason().contains("SELECT"));
    }
}
