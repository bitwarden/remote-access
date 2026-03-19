use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

use ap_client::CredentialData;

create_exception!(bw_remote_rs, RemoteAccessError, PyException);

/// Credential data returned from a request.
#[pyclass(name = "CredentialData")]
#[derive(Clone, Debug)]
pub struct PyCredentialData {
    inner: CredentialData,
}

impl From<CredentialData> for PyCredentialData {
    fn from(inner: CredentialData) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl PyCredentialData {
    #[getter]
    fn username(&self) -> Option<&str> {
        self.inner.username.as_deref()
    }

    #[getter]
    fn password(&self) -> Option<&str> {
        self.inner.password.as_deref()
    }

    #[getter]
    fn totp(&self) -> Option<&str> {
        self.inner.totp.as_deref()
    }

    #[getter]
    fn uri(&self) -> Option<&str> {
        self.inner.uri.as_deref()
    }

    #[getter]
    fn notes(&self) -> Option<&str> {
        self.inner.notes.as_deref()
    }

    fn __repr__(&self) -> String {
        format!(
            "CredentialData(username={:?}, password=***, totp={:?}, uri={:?})",
            self.inner.username, self.inner.totp, self.inner.uri,
        )
    }
}
