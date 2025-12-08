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

use chrono::Datelike;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn get_license_header() -> String {
    let year = chrono::Utc::now().year();
    format!(
        r#"
// SPDX-FileCopyrightText: Copyright {year} gematik GmbH
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
// find details in the "Readme" file."#
    )
    .trim()
    .to_string()
}

fn current_dir() -> PathBuf {
    env::current_dir().unwrap()
}

fn main() {
    build_openssl();
    build_openssl_bindings();
}

struct AndroidEnv {
    env: Vec<(String, String)>,
    api_level: String,
}

fn build_openssl() {
    const OPENSSL_VERSION: &str = "8fabfd81094d1d9f8890df4bee083aa6f77d769d";

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let target = env::var("TARGET").unwrap_or_else(|_| "aarch64-apple-darwin".to_string());
    let android_env = android_toolchain(&target);

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
    let mut configure_args = vec![
        openssl_target.to_string(),
        format!("--prefix={}", install.display()),
        // "no-asm",
        // "no-async",
        "no-egd".to_string(),
        "no-ktls".to_string(),
        "no-module".to_string(),
        "no-posix-io".to_string(),
        "no-secure-memory".to_string(),
        "no-shared".to_string(),
        "no-sock".to_string(),
        "no-stdio".to_string(),
        // "no-thread-pool",
        // "no-threads",
        "no-ui-console".to_string(),
        "no-docs".to_string(),
    ];

    if let Some(env) = &android_env {
        configure_args.push(format!("-D__ANDROID_API__={}", env.api_level));
    }

    let configure_args: Vec<&str> = configure_args.iter().map(String::as_str).collect();
    run_command_env(
        &src.join("Configure").to_str().unwrap(),
        &configure_args,
        Some(&src),
        env_slice(&android_env),
    );

    // Build & install
    let jobs = num_cpus::get().to_string();
    run_command_env("make", &[&format!("-j{}", jobs)], Some(&src), env_slice(&android_env));
    run_command_env("make", &["install"], Some(&src), env_slice(&android_env));

    // Tell Cargo where to find the built libs
    let lib_dir = locate_openssl_lib_dir(&install);
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");
}

fn get_openssl_target(target: &str) -> &'static str {
    match target {
        "aarch64-apple-darwin" => "darwin64-arm64-cc",
        "x86_64-apple-darwin" => "darwin64-x86_64-cc",
        "aarch64-apple-ios" => "ios64-xcrun",
        "aarch64-apple-ios-sim" => "iossimulator-arm64-xcrun",
        "x86_64-apple-ios" => "iossimulator-x86_64-xcrun",
        "aarch64-unknown-linux-gnu" => "linux-aarch64",
        "x86_64-unknown-linux-gnu" => "linux-x86_64",
        "aarch64-linux-android" => "android-arm64",
        "armv7-linux-androideabi" => "android-arm",
        "x86_64-linux-android" => "android-x86_64",
        "i686-linux-android" => "android-x86",
        t if t.ends_with("apple-ios-sim") => "iossimulator-arm64-xcrun",
        t if t.ends_with("apple-ios") => "ios64-xcrun",
        _ => panic!("Unsupported target triple: {target}"),
    }
}

fn run_command(prog: &str, args: &[&str], cwd: Option<&PathBuf>) {
    run_command_env(prog, args, cwd, &[]);
}

fn run_command_env(prog: &str, args: &[&str], cwd: Option<&PathBuf>, envs: &[(String, String)]) {
    let mut command = Command::new(prog);
    command.args(args);

    if let Some(dir) = cwd {
        command.current_dir(dir);
    }

    command.envs(envs.iter().map(|(k, v)| (k, v)));

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
    let install_dir = manifest_dir.join(&openssl_dir);
    let lib_dir = locate_openssl_lib_dir(&install_dir);

    // Set up library linking
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");

    // Build clang args for bindgen
    let include_path = install_dir.join("include");
    let clang_args = vec!["-I".to_string(), include_path.display().to_string()];
    let wrapper_header = manifest_dir.join("wrapper/rust_wrapper.h");

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
        .raw_line(get_license_header())
        .formatter(bindgen::Formatter::Rustfmt)
        .header(wrapper_header.display().to_string())
        .clang_args(clang_args)
        .generate()
        .expect("Unable to generate ossl");

    let bindings_path = manifest_dir.join("src/ossl.rs");
    bindings.write_to_file(&bindings_path).expect("Failed to write ossl to file");

    println!("cargo:rerun-if-changed=wrapper/rust_wrapper.h");

    cc::Build::new().file(manifest_dir.join("wrapper/rust_wrapper.c")).include(&include_path).compile("rust_wrapper");

    println!("cargo:rerun-if-changed=wrapper/rust_wrapper.c");
}

fn locate_openssl_lib_dir(install_root: &Path) -> PathBuf {
    for candidate in ["lib", "lib64"] {
        let dir = install_root.join(candidate);
        if dir.is_dir() {
            return dir;
        }
    }

    panic!("OpenSSL install directory at '{}' has no lib or lib64 directory", install_root.display());
}

fn env_slice(env: &Option<AndroidEnv>) -> &[(String, String)] {
    env.as_ref().map(|env| env.env.as_slice()).unwrap_or(&[])
}

fn android_toolchain(target: &str) -> Option<AndroidEnv> {
    if !target.contains("android") {
        return None;
    }

    let ndk_root = env::var("ANDROID_NDK_HOME")
        .or_else(|_| env::var("ANDROID_NDK_ROOT"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| panic!("ANDROID_NDK_HOME or ANDROID_NDK_ROOT must be set when building for Android"));

    let host_tag = find_ndk_host_tag(&ndk_root);
    let api_level = env::var("ANDROID_API_LEVEL")
        .or_else(|_| env::var("CARGO_NDK_ANDROID_PLATFORM"))
        .unwrap_or_else(|_| "24".to_string());

    let (clang_target, binutils_target) = match target {
        "aarch64-linux-android" => ("aarch64-linux-android", "aarch64-linux-android"),
        "armv7-linux-androideabi" => ("armv7a-linux-androideabi", "arm-linux-androideabi"),
        "x86_64-linux-android" => ("x86_64-linux-android", "x86_64-linux-android"),
        "i686-linux-android" => ("i686-linux-android", "i686-linux-android"),
        _ => return None,
    };

    let bin_dir = ndk_root.join("toolchains/llvm/prebuilt").join(host_tag).join("bin");
    let cc = bin_dir.join(format!("{clang_target}{api_level}-clang"));
    let ar = bin_dir.join(format!("{binutils_target}-ar"));
    let ranlib = bin_dir.join(format!("{binutils_target}-ranlib"));

    let mut env = vec![
        ("CC".to_string(), cc.display().to_string()),
        ("AR".to_string(), ar.display().to_string()),
        ("RANLIB".to_string(), ranlib.display().to_string()),
        ("CFLAGS".to_string(), format!("-D__ANDROID_API__={api_level}")),
    ];

    if let Ok(path) = env::var("PATH") {
        env.push(("PATH".to_string(), format!("{}:{}", bin_dir.display(), path)));
    }

    Some(AndroidEnv { env, api_level })
}

fn find_ndk_host_tag(ndk_root: &Path) -> String {
    let prebuilt = ndk_root.join("toolchains/llvm/prebuilt");
    let candidates: Vec<&str> = match env::consts::OS {
        "macos" => vec!["darwin-arm64", "darwin-x86_64"],
        "linux" => vec!["linux-x86_64"],
        "windows" => vec!["windows-x86_64"],
        _ => vec!["linux-x86_64"],
    };

    for candidate in candidates {
        let tag = prebuilt.join(candidate);
        if tag.is_dir() {
            return candidate.to_string();
        }
    }

    panic!("Could not locate a valid NDK toolchain under {}", prebuilt.display());
}
