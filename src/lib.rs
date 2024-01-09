use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::time::SystemTime;

use aws_config::meta::region::RegionProviderChain;
use aws_config::{BehaviorVersion, Region};
use aws_credential_types::provider::error::CredentialsError;
use aws_credential_types::provider::ProvideCredentials;
use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings};
use error::VaultError;
use http_body_util::BodyExt;
use hyper::body::Buf;
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::net::TcpStream;

mod api;
mod error;

pub use error::Error;
pub use hyper::Uri;

/// The authentication options to be passed into the main auth function
#[derive(Debug)]
pub struct Parameters {
    /// Optionally defined Vault IAM Server ID value to be attached
    /// as a header to the authentication request
    pub iam_server_id: Option<String>,
    /// The mount path of the AWS authentication engine in Vault
    pub mount_path: String,
    /// The role in Vault to authenticate as under the AWS engine
    pub role: String,
    /// The full Vault server address and port to send the request
    pub vault_address: Uri,
}

#[derive(Debug, Serialize)]
struct IAMPayload {
    iam_http_request_method: &'static str,
    iam_request_url: String,
    iam_request_headers: String,
    iam_request_body: String,
    role: String,
}

/// Builds the authentication request payload from the credentials
/// found in the provider chain and sends it to the designated
/// Vault server to attempt a login for the argued role
pub async fn authenticate(params: &Parameters) -> Result<api::AuthInfo, Error> {
    let payload = new_iam_payload(&params.role, &params.iam_server_id).await?;
    let url = {
        let mut uri = params.vault_address.clone().into_parts();
        uri.path_and_query = Some(
            format!("/v1/auth/{}/login", params.mount_path)
                .parse()
                .expect("Path should parse"),
        );
        Uri::from_parts(uri).expect("Parts should make up a valid Uri")
    };
    let payload = serde_json::to_string(&payload).expect("serde_json::value should serialize");
    let content_length = format!("{}", payload.len());

    let addr = {
        let host = url.host().expect("uri has no host");
        let port = url.port_u16().unwrap_or(80);
        format!("{}:{}", host, port)
    };
    let req = Request::builder()
        .uri(&url)
        .method("POST")
        .header(hyper::header::HOST, url.host().unwrap())
        .header(hyper::header::ACCEPT, "application/json")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::CONTENT_LENGTH, content_length)
        .body(payload)
        .expect("Request should parse");

    let stream = TcpStream::connect(addr).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::task::spawn(conn);

    let res = sender.send_request(req).await?;
    if !res.status().is_success() {
        let body = res.collect().await?.aggregate();
        let res: VaultError = serde_json::from_reader(body.reader())?;
        return Err(Error::VaultError(res));
    }

    let body = res.collect().await?.aggregate();
    let res: api::TokenResponse<api::AuthInfo> = serde_json::from_reader(body.reader())?;
    Ok(res.auth.ok_or(Error::EmptyToken)?)
}

/// Creates the AWS4 signed request headers and the authentication
/// payload that will be sent to Vault in the login attempt
async fn new_iam_payload(
    role: &str,
    iam_server_id: &Option<String>,
) -> Result<IAMPayload, CredentialsError> {
    //let credentials = ChainProvider::new().credentials().await?;
    let region_provider = RegionProviderChain::default_provider().or_else(Region::new("us-east-1"));
    let config = aws_config::defaults(BehaviorVersion::v2023_11_09())
        .region(region_provider)
        .load()
        .await;

    let credentials = config
        .credentials_provider()
        .ok_or(CredentialsError::not_loaded("no credentials provider"))?
        .provide_credentials()
        .await?;
    let identity = credentials.into();
    let iam_server_id = iam_server_id.as_deref();
    let payload_body = SignableBody::Bytes(b"Action=GetCallerIdentity&Version=2011-06-15");
    let headers = &[
        (
            "Content-Type",
            "application/x-www-form-urlencoded; charset=utf-8",
        ),
        ("Host", "sts.amazonaws.com"),
        (
            "Content-Length",
            "43", // payload_body.len()
        ),
    ];
    let signing_instructions = {
        let headers = headers
            .iter()
            .copied()
            .chain(iam_server_id.map(|server_id| ("X-Vault-AWS-IAM-Server-ID", server_id)));

        let signable_request =
            SignableRequest::new("POST", "https://sts.amazonaws.com/", headers, payload_body)
                .expect("SignableRequest construction should not fail");

        let signing_settings = SigningSettings::default();
        let signing_params = aws_sigv4::sign::v4::SigningParams::builder()
            .identity(&identity)
            .region("us-east-1")
            .name("sts")
            .time(SystemTime::now())
            .settings(signing_settings)
            .build()
            .expect("SigningParams construction should not fail")
            .into();

        let (signing_instructions, _signature) =
            aws_sigv4::http_request::sign(signable_request, &signing_params)
                .expect("Signing should not fail")
                .into_parts();

        signing_instructions
    };

    let signed_headers = {
        let request_headers = headers
            .iter()
            .copied()
            .chain(iam_server_id.map(|server_id| ("X-Vault-AWS-IAM-Server-ID", server_id)));

        let mut headers = HashMap::<String, Vec<String>>::new();
        for (key, value) in signing_instructions.headers().chain(request_headers) {
            match headers.entry(key.to_owned()) {
                Entry::Occupied(mut e) => {
                    e.get_mut().push(value.to_owned());
                }
                Entry::Vacant(e) => {
                    e.insert(vec![value.to_owned()]);
                }
            };
        }
        serde_json::to_string(&headers).expect("serde_json::to_string should not fail")
    };

    Ok(IAMPayload {
        iam_http_request_method: "POST",
        iam_request_url: base64::encode(b"https://sts.amazonaws.com/"),
        iam_request_headers: base64::encode(signed_headers.as_bytes()),
        iam_request_body: base64::encode(b"Action=GetCallerIdentity&Version=2011-06-15"),
        role: String::from(role),
    })
}
