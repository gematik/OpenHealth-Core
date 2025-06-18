use std::path::PathBuf;

fn current_dir() -> PathBuf {
    std::env::current_dir().unwrap()
}

fn main() {
    let manifest_dir = current_dir();
    let target = std::env::var("TARGET").unwrap();
    let openssl_target = match target.as_str() {
        "aarch64-apple-darwin" => "openssl-darwin64-arm64-cc",
        "aarch64-unknown-linux-gnu" => "openssl-linux-aarch64",
        "x86_64-unknown-linux-gnu" => "openssl-linux-x86_64",
        other => panic!("Unsupported target: {}", other),
    };

    println!(
        "cargo:rustc-link-search=native={}/{}/lib",
        manifest_dir.display(),
        openssl_target
    );
    println!("cargo:rustc-link-lib=static=crypto");

    let mut clang_args: Vec<String> = Vec::new();

    clang_args.push("-I".to_string());
    clang_args.push(format!(
        "{}/{}/include/",
        manifest_dir.display(),
        openssl_target
    ).to_string());

    bindgen::Builder::default()
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .allowlist_file(r".*(/|\\)openssl((/|\\)[^/\\]+)+\.h")
        .allowlist_file(r".*(/|\\)rust_wrapper\.h")
        .rustified_enum(r"point_conversion_form_t")
        // .rust_target(bindgen::RustTarget::Stable_1_59)
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .generate_comments(true)
        .fit_macro_constants(false)
        .size_t_is_usize(true)
        .layout_tests(true)
        .prepend_enum_name(true)
        .formatter(bindgen::Formatter::Rustfmt)
        .header(format!(
            "{}/include/rust_wrapper.h",
            manifest_dir.display()
        ))
        .clang_args(clang_args)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(format!("{}/src/bindings.rs", manifest_dir.display()))
        .expect("write bindings");
}
