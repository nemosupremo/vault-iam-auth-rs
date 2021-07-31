# Vault IAM Authentication

[![crates.io](https://img.shields.io/crates/v/vault_iam_auth.svg)](https://crates.io/crates/vault_iam_auth)
[![Released API docs](https://docs.rs/vault_iam_auth/badge.svg)](https://docs.rs/vault_iam_auth)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Tiny library for Vault authentication using the AWS IAM engine.

## Example

The `authenticate` function returns a `serde_json::Value` of the standard Vault login API response body.

```rs
use vault_iam_auth::authenticate;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let resp: serde_json::Value = authenticate("https://vault.address.com", "aws", "my-role", None).await?;
  Ok(())
}
```