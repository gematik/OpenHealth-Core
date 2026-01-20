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
}

kotlin {
    jvm {}
    androidTarget()
    jvmToolchain(21)

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(project(":healthcard"))
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.0")
            }
        }
        val jvmMain by getting
        val androidMain by getting
    }
}

android {
    namespace = "de.gematik.openhealth.healthcard.testkit"
    compileSdk = 36
    defaultConfig {
        minSdk = 24
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
