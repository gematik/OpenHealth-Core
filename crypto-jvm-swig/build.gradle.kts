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
}

group = project.findProperty("gematik.baseGroup") as String
version = project.findProperty("gematik.version") as String

val rootOutputDir = "${layout.buildDirectory.get().asFile}/generated/sources/"

java {
    withSourcesJar()
    withJavadocJar()
    sourceSets {
        main {
            java.srcDir("$rootOutputDir/java")
        }
    }

    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

val generateJniWrapper by tasks.registering(Exec::class) {
    inputs.file("$projectDir/crypto.i")
    inputs.files(fileTree("$rootDir/libs/openssl/wrapper/src"))
    // swig doesn't generate missing dirs so we let gradle create them
    outputs.dir("$rootOutputDir/java/de/gematik/openhealth/crypto/internal/interop")
    outputs.dir("$rootOutputDir/jni")
    workingDir(projectDir)
    commandLine(
        "swig",
        "-c++",
        "-java",
        "-package",
        "de.gematik.openhealth.crypto.internal.interop",
        "-I$rootDir/libs/openssl/wrapper/src",
        "-o",
        "$rootOutputDir/jni/crypto.cpp",
        "-outdir",
        "$rootOutputDir/java/de/gematik/openhealth/crypto/internal/interop",
        "crypto.i",
    )
}

val patchGeneratedJava by tasks.registering {
    val inputFile =
        file("$rootOutputDir/java/de/gematik/openhealth/crypto/internal/interop/Uint8Vector.java")
    inputs.file(inputFile)
    outputs.file(inputFile)
    doLast {
        val content = inputFile.readText()
        val patched =
            content.replace(
                "public class Uint8Vector extends java.util.AbstractList<Byte> implements java.util.RandomAccess {",
                "public class Uint8Vector extends java.util.AbstractList<Byte> implements java.util.RandomAccess, ClassHandle {",
            )
        inputFile.writeText(patched)
    }
    dependsOn(generateJniWrapper)
}

tasks.withType(JavaCompile::class) {
    dependsOn(patchGeneratedJava)
}
