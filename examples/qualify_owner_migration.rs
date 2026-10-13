//! Opens only a named offline migration candidate; never accepts the live database filename.
use hopae::{crypto::SystemClock, store::Store};
use std::{path::PathBuf, sync::Arc};
#[tokio::main]
async fn main() {
    let path = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .expect("offline candidate required"),
    );
    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some("migration-candidate.db")
    );
    assert!(path.is_file(), "candidate must already exist");
    let store = Store::open(&path, Arc::new(SystemClock), vec![], None)
        .expect("candidate migration failed");
    println!(
        "candidate schema {}",
        store.schema_version().expect("schema version")
    );
}
