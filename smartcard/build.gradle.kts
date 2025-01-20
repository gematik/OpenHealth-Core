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

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.vanniktech.mavenPublish)
}

group = "${project.findProperty("gematik.baseGroup") as String}.smartcard"
version = project.findProperty("gematik.version") as String

// val platformAttribute = Attribute.of("$group.platform", String::class.java)

kotlin {
    js("jsNode") {
//        attributes.attribute(platformAttribute, "jsnode")
        nodejs {
            useEsModules()
//            testTask {
//                useMocha {
//                    timeout = "10s"
//                }
//            }
        }
        browser { }
        generateTypeScriptDefinitions()
        binaries.library()
    }
//    js("jsBrowser") {
//        attributes.attribute(platformAttribute, "jsbrowser")
//        browser()
//        generateTypeScriptDefinitions()
// //        binaries.executable()
//    }
//    iosX64()
//    iosArm64()
//    iosSimulatorArm64()
//    linuxX64()

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
        val jsCommonMain by creating {
        }
        val jsNodeMain by getting {
            dependencies {
                implementation(npm("pcsclite", "1.0.1"))
                implementation(libs.kotlin.node)
            }
        }
        val jsNodeTest by getting {
            dependencies {
                implementation(npm("pcsclite", "1.0.1"))
                implementation(libs.kotlin.node)
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

rootProject.plugins.withType<org.jetbrains.kotlin.gradle.targets.js.yarn.YarnPlugin> {
    // used to build packages using node gyp
    rootProject.the<org.jetbrains.kotlin.gradle.targets.js.yarn.YarnRootExtension>().ignoreScripts =
        false
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

tasks.withType<org.jetbrains.kotlin.gradle.targets.js.testing.KotlinJsTest> {
    dependsOn(generateKarmaConfig)
}