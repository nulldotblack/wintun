fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    if let Ok(cargo_target_dir) = get_cargo_target_dir() {
        let mut f = std::fs::File::create(cargo_target_dir.join("build.log")).unwrap();
        use std::io::Write;
        f.write_all(format!("CARGO_TARGET_DIR: '{}'\r\n", cargo_target_dir.display()).as_bytes())?;

        // The current crate's root directory
        let crate_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);

        // The path to the DLL file, relative to the crate root, depending on the target architecture
        let dll_path = get_wintun_bin_relative_path()?;
        let src_path = crate_dir.join(dll_path);

        let dst_path = cargo_target_dir.join("examples").join("wintun.dll");

        // Copy to the target directory
        if let Err(e) = std::fs::copy(src_path, &dst_path) {
            f.write_all(format!("Failed to copy 'wintun.dll': {}\n", e).as_bytes())?;
        } else {
            f.write_all(format!("Copied 'wintun.dll' to '{}'\r\n", dst_path.display()).as_bytes())?;
        }
    }
    Ok(())
}

fn get_cargo_target_dir() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    let profile = std::env::var("PROFILE")?;
    let mut target_dir = None;
    let mut sub_path = out_dir.as_path();
    while let Some(parent) = sub_path.parent() {
        if parent.ends_with(&profile) {
            target_dir = Some(parent);
            break;
        }
        sub_path = parent;
    }
    let target_dir = target_dir.ok_or("not found")?;
    Ok(target_dir.to_path_buf())
}

fn get_wintun_bin_relative_path() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let dll_path = if cfg!(target_arch = "x86") {
        "wintun/bin/x86/wintun.dll"
    } else if cfg!(target_arch = "x86_64") {
        "wintun/bin/amd64/wintun.dll"
    } else if cfg!(target_arch = "arm") {
        "wintun/bin/arm/wintun.dll"
    } else if cfg!(target_arch = "aarch64") {
        "wintun/bin/arm64/wintun.dll"
    } else {
        return Err("Unsupported architecture".into());
    };
    Ok(dll_path.into())
}
