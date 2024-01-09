#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let params = vault_iam_auth::Parameters {
        iam_server_id: None,
        mount_path: String::from("aws"),
        role: String::from("role"),
        vault_address: match std::env::var("VAULT_ADDR") {
            Ok(addr) => addr.parse().unwrap(),
            Err(_) => "https://vault.address.com:8200".parse().unwrap(),
        },
    };

    let response = vault_iam_auth::authenticate(&params).await?;

    println!("{}", response.client_token);
    Ok(())
}
