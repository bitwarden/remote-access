use pyo3::prelude::*;

mod client;
mod storage;
mod types;

use client::PyRemoteClient;
use types::{PyCredentialData, RemoteAccessError};

/// Connect to a remote peer and request a single credential.
///
/// Convenience one-shot helper that creates a client, connects, requests,
/// and closes — all in one call.
#[pyfunction]
#[pyo3(signature = (domain, token=None, session=None, proxy_url="wss://rat1.lesspassword.dev", identity_name="python-remote"))]
fn connect_and_request(
    py: Python<'_>,
    domain: &str,
    token: Option<&str>,
    session: Option<&str>,
    proxy_url: &str,
    identity_name: &str,
) -> PyResult<PyCredentialData> {
    let mut client = PyRemoteClient::new(proxy_url, identity_name)?;
    client.connect(py, token, session)?;
    let cred = client.request_credential(py, domain)?;
    client.close(py)?;
    Ok(cred)
}

#[pymodule]
fn bw_remote_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyRemoteClient>()?;
    m.add_class::<PyCredentialData>()?;
    m.add("RemoteAccessError", m.py().get_type::<RemoteAccessError>())?;
    m.add_function(wrap_pyfunction!(connect_and_request, m)?)?;
    Ok(())
}
