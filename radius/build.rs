use std::path::Path;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let dicts_dir = Path::new(&manifest_dir).join("dicts");
    let out_dir = Path::new(&manifest_dir).join("src/dict");

    let mut dict_file_paths: Vec<std::path::PathBuf> = std::fs::read_dir(&dicts_dir)
        .unwrap_or_else(|e| {
            panic!(
                "failed to read dicts directory {}: {e}",
                dicts_dir.display()
            )
        })
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            if path.is_file() {
                Some(path)
            } else {
                None
            }
        })
        .collect();
    dict_file_paths.sort();

    let dict_file_path_refs: Vec<&Path> = dict_file_paths
        .iter()
        .map(std::path::PathBuf::as_path)
        .collect();
    code_generator::generate(&out_dir, &dict_file_path_refs);

    // Re-run this build script if any dict file changes.
    println!("cargo:rerun-if-changed={}", dicts_dir.display());
    for path in &dict_file_paths {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}
