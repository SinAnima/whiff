//! `physical.text` agrees with the system `wc` on every text fixture: lines
//! and bytes always; words and characters for UTF-8 files when a UTF-8 locale
//! is available (for other encodings `wc` depends on the locale). Skipped
//! where `wc` is missing.

use std::path::Path;
use std::process::Command;

use whiff::Engine;

fn wc(path: &Path, flag: &str, locale: Option<&str>) -> Option<u64> {
    let mut cmd = Command::new("wc");
    cmd.arg(flag).arg(path);
    if let Some(l) = locale {
        cmd.env("LC_ALL", l);
    }
    let out = cmd.output().ok().filter(|o| o.status.success())?;
    String::from_utf8_lossy(&out.stdout).split_whitespace().next()?.parse().ok()
}

/// A UTF-8 locale `wc -m` understands, if the system has one.
fn utf8_locale(sample: &Path) -> Option<&'static str> {
    // "é" is one character in a UTF-8 locale and two bytes otherwise.
    let probe = sample.with_file_name("utf8-probe.txt");
    std::fs::write(&probe, "é").ok()?;
    let found = ["C.UTF-8", "en_US.UTF-8", "C.utf8"].into_iter().find(|l| wc(&probe, "-m", Some(l)) == Some(1));
    let _ = std::fs::remove_file(probe);
    found
}

#[test]
fn counts_match_wc() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    if Command::new("wc").arg("-l").arg(fixtures.join("text/LICENSE")).output().is_err() {
        eprintln!("wc not available; skipping");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let locale = utf8_locale(&tmp.path().join("x"));
    let engine = Engine::new();
    let mut checked = 0;
    for dir in std::fs::read_dir(&fixtures).unwrap().filter_map(Result::ok) {
        for file in std::fs::read_dir(dir.path()).unwrap().filter_map(Result::ok) {
            let path = file.path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name == "SOURCE.md" || name.starts_with('.') {
                continue;
            }
            let report = engine.extract_path(&path).unwrap();
            let Some(text) = report.physical.text else { continue };
            // Lines and bytes do not depend on the encoding.
            for (flag, ours) in [("-l", text.lines), ("-c", text.bytes)] {
                assert_eq!(ours, wc(&path, flag, locale), "wc {flag} {}", path.display());
            }
            // Words and characters do: `wc` reads bytes in its locale's encoding,
            // whiff decodes legacy encodings (windows-1252, …) properly. Compare
            // them for UTF-8 (and ASCII) files only, in a UTF-8 locale.
            let bytes = std::fs::read(&path).unwrap_or_default();
            let utf8 = std::str::from_utf8(&bytes).is_ok();
            // `wc` implementations disagree on a word made of non-printing
            // characters (Info's 0x1F separators): BSD and GNU 9 count it,
            // GNU 8 (Git for Windows) does not. Skip words for such files.
            let control = bytes.iter().any(|&b| (b < 0x20 && !b"\t\n\x0b\x0c\r".contains(&b)) || b == 0x7f);
            if let (Some(l), true) = (locale, utf8) {
                if !control {
                    assert_eq!(text.words, wc(&path, "-w", Some(l)), "wc -w {}", path.display());
                }
                assert_eq!(text.chars, wc(&path, "-m", Some(l)), "wc -m {}", path.display());
            }
            checked += 1;
        }
    }
    assert!(checked > 50, "only {checked} text fixtures checked");
}
