/*
 * Copyright (c) 2024 gematik GmbH
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

import com.vanniktech.maven.publish.SonatypeHost
import okio.Path.Companion.toPath
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.vanniktech.mavenPublish)
}

group = "${project.findProperty("gematik.baseGroup") as String}.crypto"
version = project.findProperty("gematik.version") as String

kotlin {
    jvm()
    androidTarget {
//        publishLibraryVariants("release")
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_1_8)
        }
    }
    iosX64()
    iosArm64()
    iosSimulatorArm64()
    js {
        browser {
            commonWebpackConfig {
                experiments
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
//    linuxX64()

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
        val jvmMain by getting {
            dependencies {
                implementation(libs.bouncycastle.bcprov)
            }
        }
        val jvmTest by getting {
        }
        val androidMain by getting {
            dependsOn(jvmMain)
        }
        val androidUnitTest by getting {
            dependsOn(jvmTest)
        }
        val jsMain by getting {
            dependencies {
                implementation(npm("${rootDir.path}/libs/openssl/npm".toPath().toFile()))
                implementation(npm("aes-cmac", "3.0.2"))
//                implementation(libs.kotlin.node)
            }
        }
        val jsTest by getting {
        }
        all {
            languageSettings {
                optIn("kotlin.js.ExperimentalJsExport")
                optIn("de.gematik.kmp.crypto.ExperimentalCryptoApi")
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
    namespace = "org.jetbrains.kotlinx.multiplatform.library.template"
    compileSdk =
        libs.versions.android.compileSdk
            .get()
            .toInt()
    defaultConfig {
        minSdk =
            libs.versions.android.minSdk
                .get()
                .toInt()
    }
}

mavenPublishing {
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL)

    signAllPublications()

    coordinates(group.toString(), "library", version.toString())

    pom {
        name = "My library"
        description = "A library."
        inceptionYear = "2024"
        url = "https://github.com/kotlin/multiplatform-library-template/"
        licenses {
            license {
                name = "XXX"
                url = "YYY"
                distribution = "ZZZ"
            }
        }
        developers {
            developer {
                id = "XXX"
                name = "YYY"
                url = "ZZZ"
            }
        }
        scm {
            url = "XXX"
            connection = "YYY"
            developerConnection = "ZZZ"
        }
    }
}