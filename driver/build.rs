fn main() -> Result<(), wdk_build::ConfigError> {
    wdk_build::configure_wdk_binary_build()?;

    // the wdk uses the cdylib export as /entry. msvc calls that lnk4216,
    // so only suppress that warning.
    println!("cargo:rustc-link-arg=/IGNORE:4216");
    println!("cargo:rustc-link-lib=cng");

    Ok(())
}
