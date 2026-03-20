//! Cross-platform compatibility for WASM and native targets.

use std::future::Future;
use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn sleep(duration: Duration) {
    gloo_timers::future::sleep(duration).await;
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn timeout<F: Future>(
    duration: Duration,
    future: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    tokio::time::timeout(duration, future).await
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn timeout<F: Future>(
    duration: Duration,
    future: F,
) -> Result<F::Output, TimeoutError> {
    tokio::select! {
        result = future => Ok(result),
        _ = gloo_timers::future::sleep(duration) => Err(TimeoutError),
    }
}

/// Timeout error for WASM targets (mirrors `tokio::time::error::Elapsed`).
#[cfg(target_arch = "wasm32")]
#[derive(Debug)]
pub(crate) struct TimeoutError;

/// Return current time as milliseconds since UNIX epoch (cross-platform).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn now_millis() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Return current time as seconds since UNIX epoch (cross-platform).
pub(crate) fn now_seconds() -> u64 {
    now_millis() / 1000
}
