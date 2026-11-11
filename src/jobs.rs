//! Periodic jobs that must run once per interval across all replicas.
//!
//! Every replica ticks on its own. Before a run it claims the job in the
//! database: the lease row lets the job run about once per interval across
//! all of them. A run that crashes is retried at the next interval.

use std::future::Future;
use std::time::Duration;

use tokio::time::MissedTickBehavior;

use crate::store::Store;

/// The shortest gap between two runs of a job that ticks every `every`. A
/// tenth is left out so that tick jitter between replicas does not skip a run.
fn min_gap(every: Duration) -> Duration {
    every.saturating_sub(every / 10)
}

/// Runs `run` every `every` on one replica at a time. `job` names the lease
/// row. A tick whose claim fails is skipped, and the claim is tried again at
/// the next tick.
pub fn spawn_singleton<F, Fut>(store: Store, job: &'static str, every: Duration, run: F)
where
    F: Fn(Store) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let min_gap = min_gap(every);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(every);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match store.claim_job(job, min_gap).await {
                Ok(true) => run(store.clone()).await,
                Ok(false) => tracing::debug!(job, "Another replica ran the job"),
                Err(error) => tracing::warn!(%error, job, "Failed to claim the job"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_gap_leaves_a_tenth_for_jitter() {
        assert_eq!(min_gap(Duration::from_secs(3600)), Duration::from_mins(54));
        assert_eq!(min_gap(Duration::ZERO), Duration::ZERO);
    }
}
