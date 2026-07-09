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

        // Join every task in parallel: each gets the full `shutdown_timeout`
        // budget concurrently. A single hung task no longer eats the budget
        // of the others, and the timeout log is accurate per task.
        let shutdown_timeout = self.shutdown_timeout;
        let joins = tasks.into_iter().map(|task| async move {
            let ServiceTask { name, mut handle } = task;
            match tokio::time::timeout(shutdown_timeout, &mut handle).await {
                Ok(result) => Self::log_join_result(name, result),
                Err(_) => {
                    crate::warn!(
                        "[NodeSupervisor] service '{}' timed out after {:?}, aborting",
                        name,
                        shutdown_timeout
                    );
                    handle.abort();
                    // Aborted handles must still be awaited to observe the
                    // JoinError and ensure the task has fully terminated.
                    Self::log_join_result(name, handle.await);
                }
            }
        });
        futures::future::join_all(joins).await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn parallel_join_does_not_sum_per_task_timeouts() {
        let timeout = Duration::from_millis(300);
        let supervisor = NodeSupervisor::with_shutdown_timeout(timeout);
        // Three tasks that ignore cancellation: each is aborted after its own
        // timeout. With parallel join the total is ~one timeout, not three.
        for _ in 0..3 {
            supervisor.spawn("hung", async {
                loop {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }
            });
        }

        let started = Instant::now();
        supervisor.shutdown().await;
        let elapsed = started.elapsed();
        assert!(
            elapsed < timeout * 2,
            "parallel shutdown summed per-task timeouts: {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn shutdown_joins_cooperative_tasks_quickly() {
        let supervisor = NodeSupervisor::with_shutdown_timeout(Duration::from_secs(5));
        let cancel = supervisor.cancellation();
        for _ in 0..3 {
            let token = cancel.clone();
            supervisor.spawn("coop", async move {
                token.cancelled().await;
            });
        }

        let started = Instant::now();
        supervisor.shutdown().await;
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "cooperative tasks were not joined promptly"
        );
    }
}
