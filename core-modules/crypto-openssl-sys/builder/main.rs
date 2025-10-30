// SPDX-FileCopyrightText: Copyright 2025 gematik GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

use std::{env, fs, path::PathBuf, process::Command};

fn current_dir() -> PathBuf {
    env::current_dir().unwrap()
}

fn main() {
    build_openssl();
    build_openssl_bindings();
}

fn build_openssl() {
    const OPENSSL_VERSION: &str = "8fabfd81094d1d9f8890df4bee083aa6f77d769d";

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let target = env::var("TARGET").unwrap_or_else(|_| "aarch64-apple-darwin".to_string());

    let openssl_target = get_openssl_target(&target);
    let src = manifest.join("openssl-src");
    let install = manifest.join(format!("openssl-{}", openssl_target));

    // Clean & prepare
    if src.exists() {
        fs::remove_dir_all(&src).unwrap_or_else(|e| eprintln!("Warning: Failed to remove src dir: {}", e));
    }
    if install.exists() {
        fs::remove_dir_all(&install).unwrap_or_else(|e| eprintln!("Warning: Failed to remove install dir: {}", e));
    }
    fs::create_dir_all(&install).unwrap();

    // Clone & checkout
    run_command("git", &["clone", "https://github.com/openssl/openssl.git", src.to_str().unwrap()], None);
    run_command("git", &["checkout", OPENSSL_VERSION], Some(&src));

    // Configure
    let configure_args = [
        openssl_target,
        &format!("--prefix={}", install.display()),
        // "no-asm",
        // "no-async",
        "no-egd",
        "no-ktls",
        "no-module",
        "no-posix-io",
        "no-secure-memory",
        "no-shared",
        "no-sock",
        "no-stdio",
        // "no-thread-pool",
        // "no-threads",
        "no-ui-console",
        "no-docs",
    ];
    run_command(&src.join("Configure").to_str().unwrap(), &configure_args, Some(&src));

    // Build & install
    let jobs = num_cpus::get().to_string();
    run_command("make", &[&format!("-j{}", jobs)], Some(&src));
    run_command("make", &["install"], Some(&src));

    // Tell Cargo where to find the built libs
    println!("cargo:rustc-link-search=native={}", install.join("lib").display());
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");
}
fn get_openssl_target(target: &str) -> &'static str {
    match target {
        "aarch64-apple-darwin" => "darwin64-arm64-cc",
        "x86_64-apple-darwin" => "darwin64-x86_64-cc",
        "aarch64-unknown-linux-gnu" => "linux-aarch64",
        "x86_64-unknown-linux-gnu" => "linux-x86_64",
        _ => "darwin64-arm64-cc", // fallback
    }
}

fn run_command(prog: &str, args: &[&str], cwd: Option<&PathBuf>) {
    let mut command = Command::new(prog);
    command.args(args);

    if let Some(dir) = cwd {
        command.current_dir(dir);
    }

    let status = command.status().unwrap_or_else(|e| panic!("Failed to execute command '{}': {}", prog, e));

    if !status.success() {
        panic!("Command failed: {} {:?} (exit code: {:?})", prog, args, status.code());
    }
}

fn build_openssl_bindings() {
    let manifest_dir = current_dir();
    let target = env::var("TARGET").unwrap_or_else(|_| "aarch64-apple-darwin".to_string());
    let openssl_target = get_openssl_target(&target);
    let openssl_dir = format!("openssl-{}", openssl_target);

    // Set up library linking
    println!("cargo:rustc-link-search=native={}/{}/lib", manifest_dir.display(), openssl_dir);
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");

    // Build clang args for bindgen
    let include_path = format!("{}/{}/include/", manifest_dir.display(), openssl_dir);
    let clang_args = vec!["-I".to_string(), include_path.clone()];

    // Generate ossl
    let bindings = bindgen::Builder::default()
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .allowlist_file(r".*(/|\\)openssl((/|\\)[^/\\]+)+\.h")
        .allowlist_file(r".*(/|\\)rust_wrapper\.h")
        .rustified_enum(r"point_conversion_form_t")
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .generate_comments(true)
        .fit_macro_constants(false)
        .size_t_is_usize(true)
        .layout_tests(true)
        .prepend_enum_name(true)
        .formatter(bindgen::Formatter::Rustfmt)
        .header(format!("{}/wrapper/rust_wrapper.h", manifest_dir.display()))
        .clang_args(clang_args)
        .generate()
        .expect("Unable to generate ossl");

    let bindings_path = format!("{}/src/ossl.rs", manifest_dir.display());
    bindings.write_to_file(&bindings_path).expect("Failed to write ossl to file");

    println!("cargo:rerun-if-changed=wrapper/rust_wrapper.h");

    cc::Build::new()
        .file(format!("{}/wrapper/rust_wrapper.c", manifest_dir.display()))
        .include(include_path.clone())
        .compile("rust_wrapper");

    println!("cargo:rerun-if-changed=wrapper/rust_wrapper.c");
}
