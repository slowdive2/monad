fn main() -> Result<(), wdk_build::ConfigError> {
    wdk_build::configure_wdk_binary_build()?;

    // rust's cdylib export is also the /entry symbol required by the wdk.
    // msvc diagnoses that required combination as lnk4216. suppress only
    // this warning; every other linker diagnostic remains visible.
    println!("cargo:rustc-link-arg=/IGNORE:4216");
    println!("cargo:rustc-link-lib=cng");

    Ok(())
}
