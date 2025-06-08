use std::{fs, path::PathBuf};

use dotscope::metadata::cilobject::CilObject;

#[test]
/// Open all files from the fuzzer corpus, and load all of them without crashing. Can produce errors, as these are invalid files,
/// just don't crash
fn fuzzer_corpus() {
    test_load_path(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/cilobject/"));
}

#[test]
/// Open all files from the fuzzer corpus that previously caused a crash, and load all of them without crashing. Can produce errors,
/// as these are invalid files, just don't crash.
fn fuzzer_crashes() {
    test_load_path(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/artifacts/cilobject/"));
}

// #[test]
// /// Debug one specific test case
// fn debug() {
//     test_load_path(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/artifacts/cilobject/leak-b96355f49d7918e856039d2c998de850e47ffdf3"));
// }

fn test_load_path(path: PathBuf) {
    if let Ok(artifacts_path) = fs::read_dir(path) {
        for entry in artifacts_path.flatten() {
            let path = entry.path();
            if path.is_file() {
                let _ = CilObject::from_file(&path);
            }
        }
    }
}
