#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let params = vault_iam_auth::Parameters {
    iam_server_id: None,
    mount_path: String::from("aws"),
    role: String::from("my-role"),
    vault_address: String::from("https://vault.address.com:8200"),
  };

  let response: serde_json::Value = vault_iam_auth::authenticate(&params).await?;

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
