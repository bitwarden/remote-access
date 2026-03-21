use ap_client::CredentialData;
use wasm_bindgen::prelude::*;

/// Credential data returned from a request.
#[wasm_bindgen]
pub struct JsCredentialData {
    inner: CredentialData,
}

impl From<CredentialData> for JsCredentialData {
    fn from(inner: CredentialData) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl JsCredentialData {
    #[wasm_bindgen(getter)]
    pub fn username(&self) -> Option<String> {
        self.inner.username.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn password(&self) -> Option<String> {
        self.inner.password.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn totp(&self) -> Option<String> {
        self.inner.totp.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn uri(&self) -> Option<String> {
        self.inner.uri.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn notes(&self) -> Option<String> {
        self.inner.notes.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn credential_id(&self) -> Option<String> {
        self.inner.credential_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn domain(&self) -> Option<String> {
        self.inner.domain.clone()
    }

    /// Convert to a plain JS object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> JsValue {
        let obj = js_sys::Object::new();
        let set = |key: &str, val: &Option<String>| {
            let _ = js_sys::Reflect::set(
                &obj,
                &JsValue::from_str(key),
                &match val {
                    Some(s) => JsValue::from_str(s),
                    None => JsValue::NULL,
                },
            );
        };
        set("username", &self.inner.username);
        set("password", &self.inner.password);
        set("totp", &self.inner.totp);
        set("uri", &self.inner.uri);
        set("notes", &self.inner.notes);
        set("credential_id", &self.inner.credential_id);
        set("domain", &self.inner.domain);
        obj.into()
    }
}

/// Convert a ClientError into a JsValue for throwing.
pub fn client_error_to_js(err: ap_client::ClientError) -> JsValue {
    JsValue::from_str(&err.to_string())
}
