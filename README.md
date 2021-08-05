# Vault IAM Authentication

[![crates.io](https://img.shields.io/crates/v/vault_iam_auth.svg)](https://crates.io/crates/vault_iam_auth)
[![Released API docs](https://docs.rs/vault_iam_auth/badge.svg)](https://docs.rs/vault_iam_auth)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Tiny library for Vault authentication using the AWS IAM engine.

## Example

The `authenticate` function returns a `serde_json::Value` of the standard Vault login API response body.

```rust
use std::error::Error;

use serde_json::Value;
use vault_iam_auth::{authenticate, Parameters};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
  let params = Parameters {
    iam_server_id: None,
    mount_path: String::from("aws"),
    role: String::from("my-role"),
    vault_address: String::from("https://vault.address.com:8200"),
  };

  let response: serde_json::Value = authenticate(&params).await?;

  let token = response
    .get("auth")
    .unwrap()
    .get("client_token")
    .unwrap()
    .as_str()
    .unwrap();
  println!("{}", token);
  Ok(())
}
```