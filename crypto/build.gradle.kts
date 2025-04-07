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

import de.gematik.openhealth.build.applyOpenHealthMavenPublishing
import okio.Path.Companion.toPath
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.vanniktech.mavenPublish)
}

group = project.findProperty("gematik.baseGroup") as String
version = project.findProperty("gematik.version") as String

val cmakeVersion = project.findProperty("cmake.version") as? String

kotlin {
    jvm {
    }
    androidTarget {
        //        publishLibraryVariants("release")
//        compilerOptions {
//            jvmTarget.set(JvmTarget.JVM_1_8)
//        }
        compilations.all {
            compileTaskProvider.configure {
                compilerOptions {
                    jvmTarget.set(JvmTarget.JVM_17)
                }
            }
        }
    }

//    iosX64()
//    iosArm64()
//    iosSimulatorArm64()
    js {
        useEsModules()
        browser {
            commonWebpackConfig {
                experiments += "asyncWebAssembly"
            }
            webpackTask {
//                inputFiles.matching {
//                    setIncludes("${rootDir.path}/libs/openssl/npm")
//                }
            }
        }
        nodejs {}
        generateTypeScriptDefinitions()
        binaries.library()
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(project(":asn1"))
                implementation(libs.kotlinx.coroutines.core)
                implementation(libs.bignum)
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.kotlinx.coroutines.test)
            }
        }
        val jvm by creating {
            dependsOn(commonMain)
            dependencies {
                api(project(":crypto-jvm-swig"))
            }
        }
        val jvmMain by getting {
            dependsOn(jvm)
            dependencies {
                implementation(project(":crypto-jvm-lib"))
            }
        }
        val jvmTest by getting {
        }
        val androidMain by getting {
            dependsOn(jvm)
            dependencies {
                implementation(project(":crypto-jvm-lib"))
            }
        }
        val androidInstrumentedTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation(kotlin("test-junit"))
                implementation("androidx.test:runner:1.6.2")
                implementation("androidx.test.ext:junit:1.1.1")
                implementation(project(":crypto-jvm-swig"))
            }
        }
        val jsMain by getting {
            dependencies {
                api(project(":crypto-web-lib"))
                api(npm("${rootDir.path}/crypto-web-lib/npm".toPath().toFile()))
                implementation(libs.kotlin.js)
            }
        }
        val jsTest by getting {
        }
        all {
            languageSettings {
                optIn("kotlin.js.ExperimentalJsExport")
                optIn("de.gematik.openhealth.crypto.ExperimentalCryptoApi")
            }

            if (name.contains("Test")) {
                languageSettings {
                    optIn("kotlin.ExperimentalStdlibApi")
                }
            }
        }
    }
}

android {
    ndkVersion = "27.2.12479018"

    namespace = "de.gematik.openhealth.crypto"
    compileSdk =
        libs.versions.android.compileSdk
            .get()
            .toInt()
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    defaultConfig {
        minSdk =
            libs.versions.android.minSdk
                .get()
                .toInt()

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += setOf("arm64-v8a")
//            abiFilters += setOf("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
        }

        externalNativeBuild {
            cmake {
                arguments += listOf("-DPROJECT_ROOT_DIR=$rootDir")
                targets("oh_crypto")
            }
        }
    }
    externalNativeBuild {
        cmake {
            version = cmakeVersion
            path("$rootDir/libs/openssl/wrapper/CMakeLists.txt".toPath().toFile())
        }
    }
}

mavenPublishing {
    applyOpenHealthMavenPublishing(
        artifactId = "crypto",
        name = "OpenHealth Crypto",
        description = "OpenHealth Crypto Library for KMP",
        inceptionYear = "2025",
    )
}
