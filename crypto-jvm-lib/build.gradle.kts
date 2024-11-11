/*
 * Copyright 2025 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

plugins {
    id("java-library")
    id("maven-publish")
}

group = project.findProperty("gematik.baseGroup") as String
version = project.findProperty("gematik.version") as String

val rootOutputDir = "${layout.buildDirectory.get().asFile}/generated/"

java {
    sourceSets {
        main {
            resources.srcDir("$rootOutputDir/resources")
        }
    }

    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

val hostOs =
    System
        .getProperty("os.name")
        .lowercase()
        .trim()
        .replace(" ", "")
val hostArch =
    System
        .getProperty("os.arch")
        .lowercase()
        .trim()
        .replace(" ", "")

publishing {
    publications {
        create<MavenPublication>("mavenJavaPlatformArchSpecific") {
            groupId = group.toString()
            artifactId = "crypto-jvm-native"

            from(components["java"])
        }
    }
}

val cmakeSetup by tasks.registering(Exec::class) {
    dependsOn(":crypto-jvm-swig:generateJniWrapper")
    inputs.file("$rootDir/libs/openssl/wrapper/CMakeLists.txt")
    outputs.dir("${layout.buildDirectory.get().asFile}/cmake-build")
    workingDir(projectDir)
    commandLine(
        "cmake",
        "-DPROJECT_ROOT_DIR=$rootDir",
        "-GNinja",
        "-S",
        "$rootDir/libs/openssl/wrapper",
        "-B",
        "${layout.buildDirectory.get().asFile}/cmake-build",
    )
}

val cmakeBuild by tasks.registering(Exec::class) {
    dependsOn(cmakeSetup)
    inputs.dir("${layout.buildDirectory.get().asFile}/cmake-build")
    outputs.dir("${layout.buildDirectory.get().asFile}/cmake-build")
    workingDir(projectDir)
    commandLine(
        "cmake",
        "--build",
        "${layout.buildDirectory.get().asFile}/cmake-build",
        "--target",
        "oh_crypto",
    )
}

val copyNativeLibs by tasks.registering(Copy::class) {
    dependsOn(cmakeBuild)
    from("${layout.buildDirectory.get().asFile}/cmake-build") {
        include("liboh_crypto.*")
    }
    into("$rootOutputDir/resources/$hostOs-$hostArch/")
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
}

tasks.named<Jar>("jar") {
    dependsOn(copyNativeLibs)
}

tasks.named<ProcessResources>("processResources") {
    dependsOn(copyNativeLibs)
}
