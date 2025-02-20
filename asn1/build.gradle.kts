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

import com.vanniktech.maven.publish.SonatypeHost

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.vanniktech.mavenPublish)
}

group = project.findProperty("gematik.baseGroup") as String
version = project.findProperty("gematik.version") as String

kotlin {
    jvm()
//    androidTarget {
// //        publishLibraryVariants("release")
//        compilerOptions {
//            jvmTarget.set(JvmTarget.JVM_1_8)
//        }
//    }
//    iosX64()
//    iosArm64()
//    iosSimulatorArm64()
    js {
        browser {}
        nodejs {}
        generateTypeScriptDefinitions()
        binaries.library()
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                // put your multiplatform dependencies here
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(libs.kotlin.test)
            }
        }
        all {
            languageSettings {
                optIn("kotlin.js.ExperimentalJsExport")
            }

            if (name.endsWith("Test")) {
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

//    signAllPublications()

    coordinates(group.toString(), "asn1", version.toString())

    pom {
        name = "OpenHealth Asn1"
        description = "OpenHealth Asn1"
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
