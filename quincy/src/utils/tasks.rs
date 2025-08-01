use anyhow::Result;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use tokio::task::JoinHandle;

/// Joins all tasks in a FuturesUnordered or aborts them after a specified duration.
pub async fn abort_all<R>(mut tasks: FuturesUnordered<JoinHandle<R>>) -> Result<()> {
    let mut aborted_tasks = tasks
        .iter_mut()
        .map(|handle| async {
            handle.abort();
            handle.await
        })
        .collect::<FuturesUnordered<_>>();

    while aborted_tasks.next().await.is_some() {}

    Ok(())
}
