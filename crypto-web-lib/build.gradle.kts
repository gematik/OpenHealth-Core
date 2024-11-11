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
    alias(libs.plugins.kotlinMultiplatform)
}

group = project.findProperty("gematik.baseGroup") as String
version = project.findProperty("gematik.version") as String

val rootOutputDir = "${layout.buildDirectory.get().asFile}/generated/"
val emscriptenDir =
    project.findProperty("emscripten.dir") as? String ?: error("emscripten.dir property is not set")

val cmakeBuildDir = "${layout.buildDirectory.get().asFile}/cmake-build"

kotlin {
    js {
        useEsModules()
        browser {}
        nodejs {}
        binaries.library()
    }

    sourceSets {
        val jsMainGenerated by creating {
            kotlin.srcDir("$rootOutputDir/jsMainGenerated/kotlin")
            resources.srcDir("$rootOutputDir/jsMainGenerated/resources")
        }
        val jsMain by getting {
            dependsOn(jsMainGenerated)
        }
    }
}

val emcmakeSetup by tasks.registering(Exec::class) {
    inputs.file("$rootDir/libs/openssl/wrapper/CMakeLists.txt")
    outputs.dir(cmakeBuildDir)
    workingDir(projectDir)
    commandLine(
        "bash",
        "-c",
        "source ${emscriptenDir}/emsdk_env.sh && emcmake cmake -DPROJECT_ROOT_DIR=$rootDir -GNinja -S $rootDir/libs/openssl/wrapper -B ${layout.buildDirectory.get().asFile}/cmake-build"
    )
}

val emcmakeBuild by tasks.registering(Exec::class) {
    dependsOn(emcmakeSetup)
    inputs.dir(cmakeBuildDir)
    outputs.dir(cmakeBuildDir)
    workingDir(projectDir)
    commandLine(
        "bash",
        "-c",
        "source ${emscriptenDir}/emsdk_env.sh && cmake --build $cmakeBuildDir --target oh_crypto",
    )
}

val copyJsLibs by tasks.registering(Copy::class) {
    dependsOn(emcmakeBuild)
    from("${layout.buildDirectory.get().asFile}/cmake-build") {
        include("oh_crypto.*")
    }
    into("npm/lib")
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
}

val npmInstall by tasks.registering(Exec::class) {
    inputs.file("npm/package-lock.json")
    outputs.dir("npm/node_modules")
    workingDir("npm")
    commandLine("npm", "ci")
}

val npxNodeConv by tasks.registering(Exec::class) {
    inputs.file("$cmakeBuildDir/oh_crypto.d.ts")
    outputs.file("$rootOutputDir/jsMainGenerated/kotlin/de/gematik/openhealth/crypto/internal/interop/crypto.kt")
    workingDir("npm")
    commandLine(
        "npx",
        "node",
        "src/conv.ts",
        "--package-path",
        "de.gematik.openhealth.crypto.internal.interop",
        "--module-name",
        "CryptoModule",
        "$cmakeBuildDir/oh_crypto.d.ts",
        "$rootOutputDir/jsMainGenerated/kotlin/de/gematik/openhealth/crypto/internal/interop/crypto.kt"
    )
    dependsOn(emcmakeBuild)
    dependsOn(npmInstall)
}

tasks.named<ProcessResources>("jsProcessResources") {
    dependsOn(copyJsLibs, npxNodeConv)
}
