#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let response: serde_json::Value = vault_iam_auth::authenticate("https://vault.address.com", "aws", "my-role", None).await?;
  let token = response.get("auth").unwrap().get("client_token").unwrap().as_str().unwrap();
  println!("{}", token);
  Ok(())
}
