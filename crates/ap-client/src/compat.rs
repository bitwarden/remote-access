//! Cross-platform compatibility for WASM and native targets.

use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn sleep(duration: Duration) {
    gloo_timers::future::sleep(duration).await;
}
