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
import org.jetbrains.kotlin.gradle.targets.js.testing.KotlinJsTest
import org.jetbrains.kotlin.gradle.targets.js.yarn.YarnPlugin
import org.jetbrains.kotlin.gradle.targets.js.yarn.YarnRootExtension

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.vanniktech.mavenPublish)
}

group = project.findProperty("gematik.baseGroup") as String
version = project.findProperty("gematik.version") as String

kotlin {
    jvm()
    js {
        nodejs {
            useEsModules()
        }
        browser { }
        generateTypeScriptDefinitions()
        binaries.library()
    }

    applyDefaultHierarchyTemplate()

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(project(":asn1"))
                implementation(project(":crypto"))
                implementation(libs.bignum)
                implementation(libs.kotlinx.coroutines.core)
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.kotlinx.coroutines.test)
            }
        }
        all {
            languageSettings {
                optIn("kotlin.js.ExperimentalJsExport")
            }

            if (name.contains("Test")) {
                languageSettings {
                    optIn("kotlin.ExperimentalStdlibApi")
                }
            }
        }
    }
}

rootProject.plugins.withType<YarnPlugin> {
    // used to build packages using node gyp
    rootProject.the<YarnRootExtension>().ignoreScripts =
        false
}

mavenPublishing {
    applyOpenHealthMavenPublishing(
        artifactId = "smartcard",
        name = "OpenHealth Smartcard",
        description = "OpenHealth Smartcard Library for KMP",
        inceptionYear = "2025",
    )
}

val generateKarmaConfig by project.tasks.registering {
    group = "js test setup"
    description =
        "Generates a Karma configuration that increases the Mocha timeout for browser tests."

    val karmaConfigFile = layout.projectDirectory.file("karma.config.d/mocha-timeout-config.js")
    outputs.file(karmaConfigFile)

    doFirst {
        // language=javascript
        karmaConfigFile.asFile.writeText(
            """            
            // To increase the internal mocha test timeout (cannot be done from DSL)
            // https://youtrack.jetbrains.com/issue/KT-56718#focus=Comments-27-6905607.0-0
            config.set({
                client: {
                    mocha: {
                        // We put a large timeout here so we can adjust it in the tests themselves.
                        timeout: 60000
                    }
                }
            });
            """.trimIndent(),
        )
    }
}

tasks.withType<KotlinJsTest> {
    dependsOn(generateKarmaConfig)
}
