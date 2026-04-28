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

plugins {
    id("de.gematik.openhealth.uniffi-kmp-library")
}

openHealthUniffiKmp {
    artifactId.set("crypto")
    androidNamespace.set("de.gematik.openhealth.crypto")
    pomName.set("OpenHealth Crypto")
    pomDescription.set("OpenHealth cryptography utilities (KMP) backed by Rust + UniFFI")
    inceptionYear.set("2026")
}

kotlin {
    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(project(":asn1"))
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test-junit5"))
            }
        }
    }
}
