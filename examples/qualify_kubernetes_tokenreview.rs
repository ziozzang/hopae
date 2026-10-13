//! Owned fixture driver: credentials are private files, never arguments or output.
use hopae::auth_gateway::{kubernetes, runtime::Error, stable_subject};
use std::io::Read;
use zeroize::Zeroizing;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(
        args.len() == 4,
        "expected config, CA and private reviewer file paths"
    );
    let config: kubernetes::Config = serde_json::from_slice(&std::fs::read(&args[1])?)?;
    let ca = std::fs::read(&args[2])?;
    let reviewer = Zeroizing::new(std::fs::read_to_string(&args[3])?);
    let connector = kubernetes::Connector::compile(&config, &ca, reviewer)?;
    let mut input = Zeroizing::new(String::new());
    std::io::stdin().take(8193).read_to_string(&mut input)?;
    anyhow::ensure!(input.len() <= 8192, "fixture input capacity");
    let input: serde_json::Value = serde_json::from_str(&input)?;
    let now = input["now_ms"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("fixture clock required"))?;
    let token = input["token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("fixture token required"))?;
    let attempts = input["attempts"].as_u64().unwrap_or(1);
    anyhow::ensure!((1..=5).contains(&attempts), "fixture attempt capacity");
    for _ in 0..attempts {
        match connector.authenticate("orders", token, now).await {
            Ok(evidence) => println!(
                "{}",
                serde_json::json!({"status":"verified","subject":stable_subject(evidence.subject()),"kind":format!("{:?}",evidence.subject().kind),"service":evidence.service()})
            ),
            Err(Error::Invalid) => println!("{}", serde_json::json!({"status":"invalid"})),
            Err(_) => println!("{}", serde_json::json!({"status":"unavailable"})),
        }
    }
    Ok(())
}
