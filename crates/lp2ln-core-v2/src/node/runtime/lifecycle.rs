#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeLifecycleState {
    Created,
    Running,
    Stopping,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeLifecycleError {
    AlreadyStarted,
    RestartNotSupported,
}

impl std::fmt::Display for NodeLifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyStarted => write!(f, "node is already running"),
            Self::RestartNotSupported => {
                write!(f, "node restart is not supported; build a new NodeRuntime")
            }
        }
    }
}

impl std::error::Error for NodeLifecycleError {}
