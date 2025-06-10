plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.8.0"
}
rootProject.name = "rust-core"
include("kmp-module")
include("asn1")
include("asn1-ffi")
include("asn1-jni")
include("asn1-ffi-cs-tests")