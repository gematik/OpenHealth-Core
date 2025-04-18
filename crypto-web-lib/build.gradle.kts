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

val buildDirPath =
    layout.buildDirectory
        .get()
        .asFile.absolutePath

val rootOutputDir = "$buildDirPath/generated/"
var emscriptenDir = project.findProperty("emscripten.dir") as? String

val cmakeBuildDir = "$buildDirPath/cmake-build"

kotlin {
    js {
        useEsModules()
        browser {}
        nodejs {}
        binaries.library()
    }

    sourceSets {
        val jsMain by getting {
            kotlin.srcDir("$rootOutputDir/jsMainGenerated/kotlin")
            resources.srcDir("$rootOutputDir/jsMainGenerated/resources")
        }
    }
}

if (emscriptenDir == null) {
    val emscriptenGitHash = "24fc909c0da13ef641d5ae75e89b5a97f25e37aa"

    emscriptenDir = "$buildDirPath/emsdk-$emscriptenGitHash"

    tasks.register("emscriptenSetup", Exec::class) {
        val zipUrl =
            "https://github.com/emscripten-core/emsdk/archive/$emscriptenGitHash.zip"
        val zipFile = "$buildDirPath/emsdk-$emscriptenGitHash.zip"
        val outputDir = "$buildDirPath/emsdk-$emscriptenGitHash"

        outputs.dir(outputDir)
        outputs.file(zipFile)
        commandLine(
            "bash",
            "-c",
            """
            curl -L -o "$zipFile" "$zipUrl" &&
            unzip -o -q "$zipFile" -d "$outputDir/../" &&
            cd "$outputDir" &&
            ./emsdk install latest &&
            ./emsdk activate latest &&
            source ./emsdk_env.sh &&
            cd ./upstream/emscripten/ &&
            npm ci
            """.trimIndent(),
        )
    }
}

val emcmakeSetup by tasks.registering(Exec::class) {
    inputs.file("$rootDir/libs/openssl/wrapper/CMakeLists.txt")
    outputs.dir(cmakeBuildDir)
    workingDir(projectDir)
    commandLine(
        "bash",
        "-c",
        "source $emscriptenDir/emsdk_env.sh && emcmake cmake -DPROJECT_ROOT_DIR=$rootDir -GNinja -S $rootDir/libs/openssl/wrapper -B $buildDirPath/cmake-build",
    )
    tasks.findByName("emscriptenSetup")?.let { dependsOn(it) }
}

val emcmakeBuild by tasks.registering(Exec::class) {
    dependsOn(emcmakeSetup)
    inputs.dir(cmakeBuildDir)
    outputs.dir(cmakeBuildDir)
    workingDir(projectDir)
    commandLine(
        "bash",
        "-c",
        "source $emscriptenDir/emsdk_env.sh && cmake --build $cmakeBuildDir --target oh_crypto",
    )
}

val copyJsLibs by tasks.registering(Copy::class) {
    dependsOn(emcmakeBuild)
    from("$buildDirPath/cmake-build") {
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
    outputs.file(
        "$rootOutputDir/jsMainGenerated/kotlin/de/gematik/openhealth/crypto/internal/interop/crypto.kt",
    )
    workingDir("npm")
    commandLine(
        "bash",
        "-c",
        """
        source $emscriptenDir/emsdk_env.sh &&
        npx tsx src/conv.ts --package-path de.gematik.openhealth.crypto.internal.interop --module-class-name CryptoModule --module-name gematik-openhealth-internal-crypto $cmakeBuildDir/oh_crypto.d.ts $rootOutputDir/jsMainGenerated/kotlin/de/gematik/openhealth/crypto/internal/interop/crypto.kt
        """.trimIndent(),
    )
    dependsOn(emcmakeBuild)
    dependsOn(npmInstall)
}

tasks.named("compileKotlinJs") {
    dependsOn(copyJsLibs, npxNodeConv)
}

tasks.named("jsProcessResources") {
    dependsOn(copyJsLibs, npxNodeConv)
}
