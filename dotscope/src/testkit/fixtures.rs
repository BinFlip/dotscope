//! The committed test fixtures under `tests/samples`, named by their path relative to it.
//!
//! A fixture is resolved through the crate's manifest directory, never the working directory,
//! and a missing one fails the test that asked for it: a committed fixture is never skipped.
//! `tests/samples/MANIFEST.toml` lists every file with its hash, provenance and license, and the
//! unit test below holds the tree to it. An entry's `suites` are tags that select it for a tier
//! or a sweep (`quick-corpus`); they are curated by hand, like `source` and `license`.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

/// The directory the fixtures live in.
pub fn samples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples")
}

/// The path of fixture `rel`, a file or directory under `tests/samples`.
///
/// # Panics
///
/// When the fixture is missing: it is listed in `tests/samples/MANIFEST.toml` and committed.
pub fn fixture(rel: &str) -> PathBuf {
    let path = samples_dir().join(rel);
    assert!(
        path.exists(),
        "fixture `{rel}` is missing from tests/samples (every fixture is committed and listed in \
         tests/samples/MANIFEST.toml)"
    );
    path
}

/// The bytes of fixture `rel`, read once per test binary.
///
/// # Panics
///
/// When the fixture is missing or cannot be read.
pub fn fixture_bytes(rel: &str) -> &'static [u8] {
    static CACHE: OnceLock<Mutex<HashMap<String, &'static [u8]>>> = OnceLock::new();
    let mut cache = CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    cache.entry(rel.to_string()).or_insert_with(|| {
        let bytes = std::fs::read(fixture(rel))
            .unwrap_or_else(|e| panic!("fixture `{rel}` cannot be read: {e}"));
        Box::leak(bytes.into_boxed_slice())
    })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        path::Path,
        process::Command,
        time::Duration,
    };

    use sha2::{Digest, Sha256};

    use super::*;
    use crate::testkit::tools::run_with_timeout;

    /// One manifest entry: what a fixture is, where it came from, and the suites it is tagged for.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Entry {
        sha256: String,
        source: String,
        license: String,
        suites: Vec<String>,
    }

    /// The files under `root` that git would commit, by their path relative to it: tracked
    /// ones, and untracked ones the repository's ignore rules leave in (a `.DS_Store` is not a
    /// fixture). A committed file deleted from the working tree is not among them, so the
    /// manifest test reports it missing.
    fn committable(root: &Path) -> BTreeSet<String> {
        let output = run_with_timeout(
            Command::new("git")
                .args([
                    "ls-files",
                    "-z",
                    "--cached",
                    "--others",
                    "--exclude-standard",
                ])
                .args(["--", "."])
                .current_dir(root),
            Duration::from_secs(120),
        )
        .expect("git lists the fixtures");
        assert!(
            output.status.success(),
            "git ls-files: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
            .stdout
            .split(|&b| b == 0)
            .filter(|path| !path.is_empty())
            .map(|path| String::from_utf8_lossy(path).into_owned())
            .filter(|rel| rel != "MANIFEST.toml" && root.join(rel).is_file())
            .collect()
    }

    fn sha256(path: &Path) -> String {
        let bytes = fs::read(path).expect("readable");
        Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The provenance a new fixture is listed with, by where it lives. Entries already in the
    /// manifest keep theirs: it is edited by hand from then on.
    fn provenance(rel: &str) -> (&'static str, &'static str) {
        let first = rel.split('/').next().unwrap_or_default();
        let family = rel.split('/').nth(1).unwrap_or_default();
        match (first, family) {
            ("packers", "netreactor") => (
                ".NET Reactor 7.5 (licensed Windows install) over TestApp, packers/regenerate.sh",
                "TestApp Apache-2.0; the code the protector injects under the protector's license",
            ),
            ("packers", "source") => (
                "TestApp and ResourceTestApp, the sources every packer sample is built from",
                "Apache-2.0",
            ),
            ("packers", _) => (
                "sample factory (tests/samples/factory): the protector over TestApp",
                "TestApp Apache-2.0; the code the protector injects under the protector's license",
            ),
            ("factory", _) => ("the sample factory itself", "Apache-2.0"),
            ("metadata", _) | ("debug", _) => (
                "sample factory (tests/samples/factory): TestApp built or rewritten per variant",
                "test sample generated by the project from its TestApp (Apache-2.0)",
            ),
            ("winmd", _) => (
                "win32metadata project: Windows.Wdk.winmd",
                "MIT (microsoft/win32metadata)",
            ),
            ("fuzz-regressions", _) => (
                "cargo-fuzz inputs that once crashed or hung dotscope",
                "Apache-2.0",
            ),
            ("dotnet_10.0", _) => (
                ".NET 10 shared framework assemblies",
                "MIT (dotnet/runtime)",
            ),
            (mono, _) if mono.starts_with("mono_") => (
                "Mono framework assemblies of that profile",
                "mixed: Mono class libraries MIT; bundled Microsoft libraries under their own \
                 licenses",
            ),
            _ if rel.starts_with("WB_") || rel == "WindowsBase.dll" => (
                "WindowsBase.dll 8.0.6 of the .NET 8 Windows Desktop runtime (dotnet/wpf \
                 86a51738), and sections cut from it",
                "MIT (dotnet/wpf)",
            ),
            _ => ("built for dotscope's tests", "Apache-2.0"),
        }
    }

    fn quote(s: &str) -> String {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }

    fn render(manifest: &BTreeMap<String, Entry>) -> String {
        let mut text = String::from(
            "# Every committed test fixture under tests/samples: its hash, provenance, license and\n\
             # the suites it is tagged for. `source`, `license` and `suites` are edited by hand;\n\
             # after adding, changing or removing fixtures, refresh paths and hashes with\n\
             #   DOTSCOPE_WRITE_MANIFEST=1 cargo test --lib -- testkit::fixtures\n",
        );
        for (path, entry) in manifest {
            let suites: Vec<String> = entry.suites.iter().map(|s| quote(s)).collect();
            text.push_str(&format!(
                "\n[[fixture]]\npath = {}\nsha256 = {}\nsource = {}\nlicense = {}\nsuites = [{}]\n",
                quote(path),
                quote(&entry.sha256),
                quote(&entry.source),
                quote(&entry.license),
                suites.join(", ")
            ));
        }
        text
    }

    fn parse(text: &str) -> BTreeMap<String, Entry> {
        let table: toml::Table = text.parse().expect("MANIFEST.toml is TOML");
        let string = |value: &toml::Value, key: &str| {
            value
                .get(key)
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| panic!("manifest entry without `{key}`: {value}"))
                .to_string()
        };
        table
            .get("fixture")
            .and_then(toml::Value::as_array)
            .expect("[[fixture]] entries")
            .iter()
            .map(|value| {
                let suites = value
                    .get("suites")
                    .and_then(toml::Value::as_array)
                    .unwrap_or_else(|| panic!("manifest entry without `suites`: {value}"))
                    .iter()
                    .map(|s| s.as_str().expect("a suite is a string").to_string())
                    .collect();
                (
                    string(value, "path"),
                    Entry {
                        sha256: string(value, "sha256"),
                        source: string(value, "source"),
                        license: string(value, "license"),
                        suites,
                    },
                )
            })
            .collect()
    }

    /// The manifest after a refresh: the tree's files and hashes, each listed entry keeping its
    /// hand-written fields, each new one taking its provenance from where it lives.
    fn refreshed(
        listed: &BTreeMap<String, Entry>,
        tree: &BTreeMap<String, String>,
    ) -> BTreeMap<String, Entry> {
        tree.iter()
            .map(|(path, sha256)| {
                let entry = listed.get(path).cloned().unwrap_or_else(|| {
                    let (source, license) = provenance(path);
                    Entry {
                        sha256: String::new(),
                        source: source.to_string(),
                        license: license.to_string(),
                        suites: Vec::new(),
                    }
                });
                let entry = Entry {
                    sha256: sha256.clone(),
                    ..entry
                };
                (path.clone(), entry)
            })
            .collect()
    }

    #[test]
    fn the_manifest_lists_every_fixture_as_it_is() {
        let root = samples_dir();
        let path = root.join("MANIFEST.toml");
        let tree: BTreeMap<String, String> = committable(&root)
            .into_iter()
            .map(|rel| {
                let hash = sha256(&root.join(&rel));
                (rel, hash)
            })
            .collect();
        let text = fs::read_to_string(&path).unwrap_or_default();
        if std::env::var_os("DOTSCOPE_WRITE_MANIFEST").is_some() {
            let listed = if text.is_empty() {
                BTreeMap::new()
            } else {
                parse(&text)
            };
            fs::write(&path, render(&refreshed(&listed, &tree))).expect("writable");
        }
        let listed = parse(&fs::read_to_string(&path).expect("tests/samples/MANIFEST.toml"));

        let unlisted: Vec<&String> = tree.keys().filter(|p| !listed.contains_key(*p)).collect();
        let missing: Vec<&String> = listed.keys().filter(|p| !tree.contains_key(*p)).collect();
        let changed: Vec<&String> = tree
            .iter()
            .filter(|(p, hash)| listed.get(*p).is_some_and(|e| e.sha256 != **hash))
            .map(|(p, _)| p)
            .collect();
        assert!(
            unlisted.is_empty() && missing.is_empty() && changed.is_empty(),
            "tests/samples and MANIFEST.toml disagree: unlisted {unlisted:?}, missing {missing:?}, \
             changed {changed:?} (refresh with DOTSCOPE_WRITE_MANIFEST=1)"
        );
    }

    #[test]
    fn a_refresh_keeps_the_hand_written_fields() {
        let listed = BTreeMap::from([
            (
                "kept.exe".to_string(),
                Entry {
                    sha256: "old".to_string(),
                    source: "by hand".to_string(),
                    license: "MIT".to_string(),
                    suites: vec!["quick-corpus".to_string()],
                },
            ),
            (
                "removed.exe".to_string(),
                Entry {
                    sha256: "gone".to_string(),
                    source: String::new(),
                    license: String::new(),
                    suites: Vec::new(),
                },
            ),
        ]);
        let tree = BTreeMap::from([
            ("kept.exe".to_string(), "new".to_string()),
            ("mono_4.8/added.dll".to_string(), "fresh".to_string()),
        ]);
        let manifest = refreshed(&listed, &tree);
        assert_eq!(
            manifest.keys().collect::<Vec<_>>(),
            ["kept.exe", "mono_4.8/added.dll"]
        );
        assert_eq!(
            manifest["kept.exe"],
            Entry {
                sha256: "new".to_string(),
                ..listed["kept.exe"].clone()
            }
        );
        assert_eq!(manifest["mono_4.8/added.dll"].sha256, "fresh");
        assert_eq!(
            manifest["mono_4.8/added.dll"].source,
            provenance("mono_4.8/added.dll").0
        );
        assert_eq!(parse(&render(&manifest)), manifest);
    }

    #[test]
    fn a_fixture_resolves_through_the_manifest_directory() {
        let path = fixture("crafted_2.exe");
        assert!(path.is_absolute());
        assert_eq!(
            fixture_bytes("crafted_2.exe"),
            fs::read(&path).expect("readable")
        );
    }

    #[test]
    #[should_panic(expected = "fixture `no/such/fixture.exe` is missing")]
    fn a_missing_fixture_fails_the_test() {
        let _ = fixture("no/such/fixture.exe");
    }
}
