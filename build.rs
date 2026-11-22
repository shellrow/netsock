fn main() {
    println!("cargo:rerun-if-env-changed=DOCS_RS");
    // Rustdoc needs the Rust signatures only. The docs.rs builders lack the native SDKs.
    if std::env::var_os("DOCS_RS").is_some() {
        return;
    }
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if matches!(os.as_str(), "macos" | "freebsd" | "netbsd" | "openbsd") {
        let source = format!("src/sys/{os}/socket.c");
        println!("cargo:rerun-if-changed={source}");
        println!("cargo:rerun-if-changed=src/sys/bsd.h");
        if matches!(os.as_str(), "netbsd" | "openbsd") {
            println!("cargo:rerun-if-changed=src/sys/bsd_sysctl.h");
        }
        cc::Build::new().file(source).compile("netsock_bsd");
        if os == "freebsd" {
            println!("cargo:rustc-link-lib=util");
        }
    } else {
        println!("cargo:rerun-if-changed=build.rs");
    }
}
