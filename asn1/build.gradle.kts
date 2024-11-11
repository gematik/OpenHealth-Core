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

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.vanniktech.mavenPublish)
}

project.group = project.findProperty("gematik.baseGroup") as String
project.version = project.findProperty("gematik.version") as String

kotlin {
    jvm()
    js {
        browser {}
        nodejs {}
        generateTypeScriptDefinitions()
        binaries.library()
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
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

mavenPublishing {
    applyOpenHealthMavenPublishing(
        artifactId = "asn1",
        name = "OpenHealth Asn1",
        description = "OpenHealth Asn1 Library for KMP",
        inceptionYear = "2025",
    )
}
