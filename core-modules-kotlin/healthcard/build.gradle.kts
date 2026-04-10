// SPDX-FileCopyrightText: Copyright 2025 - 2026 gematik GmbH
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

plugins {
    id("de.gematik.openhealth.uniffi-kmp-library")
}

openHealthUniffiKmp {
    artifactId.set("healthcard")
    androidNamespace.set("de.gematik.openhealth.healthcard")
    pomName.set("OpenHealth Smartcard")
    pomDescription.set("OpenHealth Smartcard Library for KMP")
    inceptionYear.set("2025")
}

kotlin {
    sourceSets {
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
        val androidDeviceTest by getting {
            dependencies {
                implementation(project(":healthcard-testkit"))
                implementation(kotlin("test"))
                implementation("androidx.test.ext:junit:1.3.0")
                implementation("androidx.test:runner:1.7.0")
            }
        }
        val jvmTest by getting {
            dependencies {
                implementation(project(":healthcard-testkit"))
                implementation(kotlin("test"))
            }
        }
    }
}
