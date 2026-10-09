//! Optional, authenticated connection to the separately owned API service.
use crate::protocol::rendezvous::{
    ControlPermissions, ControlledContext, HeaderEntry, HttpProxyRequest, HttpProxyResponse,
};
use hbb_common::{bail, ResultType};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub fn configured() -> bool {
    !std::env::var("RUSTDESK_API_INTERNAL_URL")
        .unwrap_or_default()
        .is_empty()
}
fn client() -> ResultType<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()?)
}
fn base_url() -> ResultType<reqwest::Url> {
    let url = reqwest::Url::parse(&std::env::var("RUSTDESK_API_INTERNAL_URL")?)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("Invalid API origin");
    }
    Ok(url)
}
async fn internal<T: Serialize>(path: &str, body: &T) -> ResultType<reqwest::Response> {
    let secret =
        std::env::var("RUSTDESK_API_CLIENT_COMPATIBILITY_INTERNAL_SECRET").unwrap_or_default();
    if secret.len() < 32 {
        bail!("API integration secret must have at least 32 bytes");
    }
    let res = client()?
        .post(base_url()?.join(path)?)
        .bearer_auth(secret)
        .json(body)
        .send()
        .await?;
    if !res.status().is_success() {
        bail!("API rejected request ({})", res.status());
    }
    Ok(res)
}
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub allowed: bool,
    pub permissions: u64,
    pub conn_audit_ref: String,
}
impl Policy {
    pub fn permissions(&self) -> Option<ControlPermissions> {
        (self.permissions != 0).then(|| ControlPermissions {
            permissions: self.permissions,
            ..Default::default()
        })
    }
    pub fn context(&self) -> Option<ControlledContext> {
        (!self.conn_audit_ref.is_empty()).then(|| ControlledContext {
            conn_audit_ref: self.conn_audit_ref.clone(),
            ..Default::default()
        })
    }
}
pub async fn authorize(
    id: &str,
    token: &str,
    switch_code: &str,
    must_login: bool,
    uuid: &[u8],
    pk: &[u8],
) -> ResultType<Policy> {
    let policy:Policy=internal("/api/internal/client/authorize",&serde_json::json!({"id":id,"token":token,"switch_code":switch_code,"must_login":must_login,"uuid":base64::encode(uuid),"pk":base64::encode(pk)})).await?.json().await?;
    if !policy.allowed
        || policy.permissions >> 26 != 0
        || (0..13).any(|i| (policy.permissions >> (i * 2)) & 3 == 3)
        || policy.conn_audit_ref.len() > 64
    {
        bail!("Invalid API policy");
    }
    Ok(policy)
}
pub async fn admitted(id: &str, uuid: &[u8], pk: &[u8], source_ip: &str) -> ResultType<bool> {
    let response: Policy = internal(
        "/api/internal/client/admission",
        &serde_json::json!({"id":id,"uuid":base64::encode(uuid),"pk":base64::encode(pk),"source_ip":source_ip}),
    )
    .await?
    .json()
    .await?;
    Ok(response.allowed)
}

fn proxy_path(path: &str) -> bool {
    // Only client endpoints. Exclude internal/admin, encoded traversal and redirects.
    let endpoint = path.split('?').next().unwrap_or_default();
    !path.contains(['\\', '\r', '\n', '#'])
        && !endpoint.contains('%')
        && !endpoint.split('/').any(|s| s == "." || s == "..")
        && (matches!(
            endpoint,
            "/api/login"
                | "/api/login-options"
                | "/api/logout"
                | "/api/currentUser"
                | "/api/user/info"
                | "/api/heartbeat"
                | "/api/sysinfo"
                | "/api/sysinfo_ver"
                | "/api/users"
                | "/api/peers"
                | "/api/switch-grant"
                | "/api/devices/deploy"
                | "/api/ab"
        ) || endpoint.starts_with("/api/ab/")
            || endpoint.starts_with("/api/audit/")
            || endpoint.starts_with("/api/oidc/")
            || endpoint == "/api/device-group/accessible")
}
pub async fn proxy(
    request: HttpProxyRequest,
    ip: std::net::IpAddr,
) -> ResultType<HttpProxyResponse> {
    if !proxy_path(&request.path)
        || request.body.len() > 48 * 1024
        || request.headers.len() > 32
        || !matches!(
            request.method.as_str(),
            "GET" | "POST" | "PUT" | "DELETE" | "PATCH"
        )
    {
        bail!("Unsupported API proxy request");
    }
    let method = reqwest::Method::from_bytes(request.method.as_bytes())?;
    let mut builder = client()?
        .request(method, base_url()?.join(&request.path)?)
        .header("X-Forwarded-For", ip.to_string());
    for h in request.headers {
        if matches!(
            h.name.to_ascii_lowercase().as_str(),
            "authorization" | "content-type" | "accept" | "accept-language"
        ) && h.value.len() <= 8192
        {
            builder = builder.header(&h.name, &h.value);
        }
    }
    let mut response = builder.body(request.body.to_vec()).send().await?;
    let status = response.status().as_u16() as i32;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > 48 * 1024 {
            bail!("API proxy response too large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(HttpProxyResponse {
        status,
        body: body.into(),
        headers: vec![HeaderEntry {
            name: "content-type".into(),
            value: "application/json".into(),
            ..Default::default()
        }],
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proxy_cannot_reach_administration_or_other_origins() {
        for p in [
            "https://example.org/api/login",
            "//example.org/api/login",
            "/api/internal/client/authorize",
            "/api/admin/user/list",
            "/api/ab/../admin",
            "/api/ab/%2e%2e/admin",
            "/api/ab/\\admin",
        ] {
            assert!(!proxy_path(p), "{p}");
        }
        assert!(proxy_path("/api/login"));
        assert!(proxy_path("/api/ab/peers?current=1"));
    }
}
