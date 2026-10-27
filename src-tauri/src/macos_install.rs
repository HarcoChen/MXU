//! Run before initializing Tauri: DMG bundles must never write configuration in place.
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn run(command: &mut Command) -> Result<Output, String> {
    let output = command.output().map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
    }
}

fn text() -> serde_json::Value {
    let locales: serde_json::Value =
        serde_json::from_str(include_str!("../../src/i18n/locales/macos-install.json")).unwrap();
    let languages = Command::new("/usr/bin/defaults")
        .args(["read", "-g", "AppleLanguages"])
        .output()
        .ok();
    let language = languages
        .as_ref()
        .map(|o| String::from_utf8_lossy(&o.stdout))
        .unwrap_or_default();
    let first = language.lines().nth(1).unwrap_or("").trim();
    let key = if first.contains("zh-Hant") || first.contains("zh-TW") || first.contains("zh-HK") {
        "zh-TW"
    } else if first.contains("zh") {
        "zh-CN"
    } else if first.contains("ja") {
        "ja-JP"
    } else if first.contains("ko") {
        "ko-KR"
    } else {
        "en-US"
    };
    locales[key].clone()
}

// Arguments are passed through argv; app paths and diagnostics never become AppleScript code.
fn show_error(error: &str, strings: &serde_json::Value) {
    let message = format!("{}\n\n{error}", strings["failed"].as_str().unwrap());
    let script = "on run argv\ndisplay dialog (item 1 of argv) with title (item 2 of argv) buttons {item 3 of argv} default button 1 with icon stop\nend run";
    let _ = run(Command::new("/usr/bin/osascript").args([
        "-e",
        script,
        "--",
        &message,
        strings["title"].as_str().unwrap(),
        strings["quit"].as_str().unwrap(),
    ]));
}

// Gatekeeper runs quarantined bundles through a read-only nullfs mount. Its mount
// source is the original .app; resolve it without private Security framework APIs.
fn original_bundle(bundle: &Path) -> Result<PathBuf, String> {
    use std::{
        ffi::{CStr, CString, OsStr},
        os::unix::ffi::{OsStrExt, OsStringExt},
    };
    let path = CString::new(bundle.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: path is NUL-terminated and statfs initializes info on success.
    if unsafe { libc::statfs(path.as_ptr(), info.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let info = unsafe { info.assume_init() };
    // SAFETY: statfs returns NUL-terminated filesystem and mount source names.
    let filesystem = unsafe { CStr::from_ptr(info.f_fstypename.as_ptr()) };
    let source = unsafe { CStr::from_ptr(info.f_mntfromname.as_ptr()) };
    let source = PathBuf::from(std::ffi::OsString::from_vec(source.to_bytes().to_vec()));
    if filesystem.to_bytes() == b"nullfs" && source.extension() == Some(OsStr::new("app")) {
        source.canonicalize().map_err(|e| e.to_string())
    } else {
        Ok(bundle.to_path_buf())
    }
}

fn disk_image_bundle() -> Result<Option<PathBuf>, String> {
    let exe = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let Some(bundle) = exe
        .ancestors()
        .find(|p| p.extension().is_some_and(|e| e == "app"))
    else {
        return Ok(None);
    };
    let bundle = original_bundle(bundle)?;
    let output = run(Command::new("/usr/bin/hdiutil").args(["info", "-plist"]))?;
    let info =
        plist::Value::from_reader_xml(output.stdout.as_slice()).map_err(|e| e.to_string())?;
    let mounted = info
        .as_dictionary()
        .and_then(|d| d.get("images"))
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_dictionary()?.get("system-entities")?.as_array())
        .flatten()
        .filter_map(|v| v.as_dictionary()?.get("mount-point")?.as_string())
        .any(|mount| bundle.starts_with(Path::new(mount)));
    Ok(mounted.then(|| bundle.to_path_buf()))
}

fn install(bundle: &Path, strings: &serde_json::Value) -> Result<(), String> {
    let name = bundle.file_name().ok_or("Missing bundle name")?;
    let destination = Path::new("/Applications").join(name);
    if destination.symlink_metadata().is_ok() {
        return Err(strings["exists"].as_str().unwrap().to_owned());
    }
    // Staging on the destination volume allows an atomic rename and automatic cleanup on failure.
    let staging = tempfile::Builder::new()
        .prefix(".mxu-install-")
        .tempdir_in("/Applications")
        .map_err(|e| e.to_string())?;
    let copy = staging.path().join(name);
    run(Command::new("/usr/bin/ditto").arg(bundle).arg(&copy))?;
    run(Command::new("/usr/bin/codesign")
        .args(["--verify", "--deep", "--strict"])
        .arg(&copy))?;
    // RENAME_EXCL avoids replacing a destination created while copying.
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(copy.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let to =
        std::ffi::CString::new(destination.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    if unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    run(Command::new("/usr/bin/open")
        .arg("-n")
        .arg(&destination)
        .arg("--args")
        .args(std::env::args_os().skip(1)))?;
    Ok(())
}

/// True means the original process must exit after installation or an error.
pub fn handle_launch() -> bool {
    let bundle = match disk_image_bundle() {
        Ok(Some(bundle)) => bundle,
        Ok(None) => return false,
        Err(error) => {
            eprintln!("DMG detection failed: {error}");
            show_error(&error, &text());
            return true;
        }
    };
    let strings = text();
    if let Err(error) = install(&bundle, &strings) {
        show_error(&error, &strings);
    }
    true
}
