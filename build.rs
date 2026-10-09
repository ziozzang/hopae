// Re-run the build when an embedded migration changes (include_str! tracks the
// files itself; this also catches added files in the directory).
fn main() {
    println!("cargo:rerun-if-changed=src/store/migrations");
}
