fn main() {
    #[cfg(target_os = "freebsd")]
    {
        println!("cargo:rustc-link-lib=procstat");
    }
}
