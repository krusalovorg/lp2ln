use std::sync::Mutex;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

struct ServiceTask {
    name: &'static str,
    handle: JoinHandle<()>,
}

pub(crate) struct NodeSupervisor {
    cancellation: CancellationToken,
    tasks: Mutex<Vec<ServiceTask>>,
    shutdown_timeout: Duration,
}

impl NodeSupervisor {
    pub fn new() -> Self {
        Self {
            cancellation: CancellationToken::new(),
            tasks: Mutex::new(Vec::new()),
            shutdown_timeout: Duration::from_secs(10),
        }
    }

    #[allow(dead_code)]
    #[cfg(test)]
    pub fn with_shutdown_timeout(shutdown_timeout: Duration) -> Self {
        Self {
            cancellation: CancellationToken::new(),
            tasks: Mutex::new(Vec::new()),
            shutdown_timeout,
        }
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub fn spawn<F>(&self, name: &'static str, fut: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let handle = tokio::spawn(fut);
        if let Ok(mut tasks) = self.tasks.lock() {
            tasks.push(ServiceTask { name, handle });
        }
    }

    pub(crate) fn active_task_count(&self) -> usize {
        self.tasks
            .lock()
            .map(|tasks| tasks.iter().filter(|t| !t.handle.is_finished()).count())
            .unwrap_or(0)
    }

    pub async fn shutdown(self) {
        self.cancellation.cancel();

        // Handles are taken out of the registry before any `.await`,
        // so the Mutex guard is never held across an await point.
        let tasks = match self.tasks.lock() {
            Ok(mut guard) => std::mem::take(&mut *guard),
            Err(poison) => std::mem::take(&mut *poison.into_inner()),
        };

        let deadline = tokio::time::Instant::now() + self.shutdown_timeout;

        for mut task in tasks {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() && !task.handle.is_finished() {
                crate::warn!(
                    "[NodeSupervisor] shutdown timeout elapsed, aborting service '{}'",
                    task.name
                );
                task.handle.abort();
                Self::log_join_result(task.name, task.handle.await);
                continue;
            }

            match tokio::time::timeout(remaining, &mut task.handle).await {
                Ok(result) => Self::log_join_result(task.name, result),
                Err(_) => {
                    crate::warn!(
                        "[NodeSupervisor] service '{}' timed out after {:?}, aborting",
                        task.name,
                        self.shutdown_timeout
                    );
                    task.handle.abort();
                    // Aborted handles must still be awaited to observe the
                    // JoinError and ensure the task has fully terminated.
                    Self::log_join_result(task.name, task.handle.await);
                }
            }
        }
    }

    fn log_join_result(name: &'static str, result: Result<(), tokio::task::JoinError>) {
        match result {
            Ok(()) => {}
            Err(err) if err.is_panic() => {
                crate::error!("[NodeSupervisor] service '{}' panicked: {:?}", name, err);
            }
            Err(err) if err.is_cancelled() => {
                crate::warn!("[NodeSupervisor] service '{}' aborted", name);
            }
            Err(err) => {
                crate::warn!("[NodeSupervisor] service '{}' join error: {:?}", name, err);
            }
        }
    }
}
