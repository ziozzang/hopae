//! Publish only to a named offline candidate using the real owner transaction.
use hopae::auth_gateway::{authority::Authority, publication};
use std::path::PathBuf;
fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    anyhow::ensure!(
        args.len() == 2,
        "candidate database and configuration required"
    );
    let database = PathBuf::from(&args[0]);
    anyhow::ensure!(
        database.file_name().and_then(|s| s.to_str()) == Some("profile-publication-candidate.db"),
        "offline candidate filename required"
    );
    let metadata = std::fs::symlink_metadata(&database)?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "regular candidate required"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(
            metadata.nlink() == 1 && metadata.mode() & 0o077 == 0,
            "private independent candidate required"
        );
    }
    let config = hopae::config::load(&PathBuf::from(&args[1]))?;
    let desired = config.authentication_gateway.clone();
    let validate = |profiles: &hopae::auth_gateway::runtime::Config| {
        let mut candidate = config.clone();
        candidate.authentication_gateway = Some(profiles.clone());
        candidate
            .validate()
            .map_err(|_| publication::Error::Invalid)
    };
    let env = |name: &str| std::env::var(name).ok();
    let mut connection = rusqlite::Connection::open(&database)?;
    let mut authority = Authority::load(&mut connection, desired.clone(), &env, &validate)?;
    let revision = publication::read(&connection)?
        .ok_or(publication::Error::Invalid)?
        .revision;
    let document = authority.publish(
        &mut connection,
        revision,
        desired.clone(),
        "owned-qualification",
        &env,
        &validate,
    )?;
    anyhow::ensure!(
        document
            .configuration
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()?
            == desired.as_ref().map(serde_json::to_vec).transpose()?,
        "published configuration mismatch"
    );
    println!("candidate profile revision {}", document.revision);
    Ok(())
}
