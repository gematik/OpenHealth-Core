// SPDX-FileCopyrightText: Copyright 2026 gematik GmbH
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

import org.gradle.api.JavaVersion

plugins {
    kotlin("multiplatform")
    id("com.android.library")
    id("com.vanniktech.maven.publish")
}

group = "de.gematik.openhealth"

val generatedOutRoot: Provider<String> = providers.environmentVariable("OUT_ROOT")
    .orElse(layout.buildDirectory.dir("generated/uniffi").map { it.asFile.absolutePath })
val generatedKotlinDir: String = generatedOutRoot.map { "$it/kotlin" }.get()
val generatedResourcesDir: String = generatedOutRoot.map { "$it/resources" }.get()
val generatedJniLibsDir: String = generatedOutRoot.map { "$it/android-jni" }.get()

kotlin {
    jvm {}
    androidTarget {
        publishLibraryVariants("release")
    }
    jvmToolchain(21)

    sourceSets {
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
        val jvmMain by getting {
            kotlin.srcDir(generatedKotlinDir)
            resources.srcDir(generatedResourcesDir)
            dependencies {
                implementation("net.java.dev.jna:jna:5.18.1")
            }
        }
        val androidMain by getting {
            kotlin.srcDir(generatedKotlinDir)
            dependencies {
                implementation("net.java.dev.jna:jna:5.18.1@aar")
            }
        }
    }
}

android {
    namespace = "de.gematik.openhealth.crypto"
    compileSdk = 36
    defaultConfig {
        minSdk = 24
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets["main"].jniLibs.srcDir(generatedJniLibsDir)
    lint {
        checkGeneratedSources = false
        disable += "NewApi"
    }
    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

mavenPublishing {
    publishToMavenCentral()

    coordinates(artifactId = "crypto")

    pom {
        name = "OpenHealth Crypto"
        description = "OpenHealth Crypto Library for KMP"
        inceptionYear = "2025"
        url = "https://github.com/gematik/OpenHealth-Core"
        licenses {
            license {
                name = "Apache 2.0"
                url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
                distribution = "repo"
            }
        }
        developers {
            developer {
                name = "gematik GmbH"
                url = "https://github.com/gematik"
            }
        }
        scm {
            url = "https://github.com/gematik/OpenHealth-Core"
            connection = "scm:git:https://github.com/gematik/OpenHealth-Core.git"
            developerConnection = "scm:git:https://github.com/gematik/OpenHealth-Core.git"
        }
    }
}
