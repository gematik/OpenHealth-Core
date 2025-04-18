import org.jetbrains.dokka.DokkaDefaults.pluginsConfiguration
import java.util.Properties

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

plugins {
    alias(libs.plugins.androidLibrary) apply false
    alias(libs.plugins.kotlinMultiplatform) apply false
    alias(libs.plugins.vanniktech.mavenPublish) apply false
    jacoco

    alias(libs.plugins.detekt) apply true
    alias(libs.plugins.dokka) apply true

    id("org.jetbrains.kotlinx.binary-compatibility-validator") version "0.16.3"

    id("de.gematik.openhealth.build")
}

allprojects {
    apply(plugin = "jacoco")
}

// ./gradlew clean test jacocoRootReport -> build/reports/jacoco/jacocoRootReport/html/index.html
tasks.register<JacocoReport>("jacocoRootReport") {
    val testTasks =
        subprojects.flatMap {
            it.tasks.withType<Test>()
        }
    dependsOn(testTasks)

    additionalSourceDirs.setFrom(
        files(
            subprojects.flatMap { project ->
                listOf(
                    "${project.projectDir}/src/commonMain/kotlin",
                )
            },
        ),
    )
    sourceDirectories.setFrom(additionalSourceDirs)
    classDirectories.setFrom(
        files(
            subprojects.map { project ->
                fileTree(project.layout.buildDirectory) {
                    include("classes/kotlin/jvm/main/**")
                    include("tmp/kotlin-classes/jvmMain/**")
                    // Exclude exchange package (needs virtual health card for testing)
                    exclude("**/de/gematik/openhealth/smartcard/*exchange*/**")
                    exclude("**/de/gematik/openhealth/smartcard/*utils*/**")
                    exclude("**/de/gematik/openhealth/crypto/ByteUnit*")
                    exclude("**/de/gematik/openhealth/**/*Exception*")
                    exclude("**/de/gematik/openhealth/crypto/CmacAlgorithm*")
                }
            },
        ),
    )
    executionData.setFrom(
        project.fileTree(".") {
            include("**/build/jacoco/*.exec")
            include("**/jacoco.exec")
        },
    )

    reports {
        xml.required.set(true)
        html.required.set(true)
    }
}

subprojects {
    apply(plugin = "org.jetbrains.dokka")
    dokka {
        pluginsConfiguration.html {
            customStyleSheets.from(rootDir.resolve("config/dokka/dokkaStyle.css"))
            customAssets.from(rootDir.resolve("config/dokka/gematik_logo_white.svg"))
            footerMessage.set("(c) Gematik GmbH")
        }
    }
    tasks.withType<Test> {
        finalizedBy(tasks.withType<JacocoReport>())
    }

    tasks.withType<JacocoReport> {
        dependsOn(tasks.withType<Test>())
        reports {
            xml.required.set(true)
            html.required.set(true)
        }
    }
}

tasks.register<JacocoCoverageVerification>("jacocoRootVerification") {
    dependsOn("jacocoRootReport")

    additionalSourceDirs.setFrom(
        files(
            subprojects.flatMap { project ->
                listOf(
                    "${project.projectDir}/src/commonMain/kotlin",
                )
            },
        ),
    )
    sourceDirectories.setFrom(
        (tasks.named("jacocoRootReport").get() as JacocoReport).sourceDirectories,
    )
    classDirectories.setFrom(
        files(
            (tasks.named("jacocoRootReport").get() as JacocoReport).classDirectories.files.map {
                fileTree(it) {
                    exclude(
                        "**/*Impl*",
                        "*.internal.*",
                        "*.Generated*",
                    )
                }
            },
        ),
    )
    executionData.setFrom((tasks.named("jacocoRootReport").get() as JacocoReport).executionData)

    violationRules {
        rule {
            element = "CLASS"

            limit {
                counter = "LINE"
                value = "COVEREDRATIO"
                minimum = BigDecimal.valueOf(0.6)
            }
            excludes =
                listOf(
                    "**/*Impl*",
                    "*.internal.*",
                    "*.Generated*",
                )
        }
    }
}

val localProperties = Properties()
file("local.properties").takeIf { it.exists() }?.inputStream()?.use { localProperties.load(it) }
project.extensions.extraProperties["emscripten.dir"] = localProperties.getProperty("emscripten.dir")

// /
// / Detekt
// /

detekt {
    buildUponDefaultConfig = true
    source.from(
        files(
            fileTree(".") {
                include("**/src/**/*.kt")
                exclude("**/build/**", "**/generated/**")
            },
        ),
    )
}

dokka {
    moduleName.set("OpenHealth - Core")

    dokkaPublications.html {
        outputDirectory.set(rootDir.resolve("docs/api"))
        includes.from(project.layout.projectDirectory.file("README.md"))
    }

    pluginsConfiguration.html {
        customStyleSheets.from(rootDir.resolve("config/dokka/dokkaStyle.css"))
        customAssets.from(rootDir.resolve("config/dokka/gematik_logo_white.svg"))
        footerMessage.set("© Gematik GmbH")
    }
}

val ktlint by configurations.creating

dependencies {
    dokka(project(":asn1"))
    dokka(project(":crypto"))
    dokka(project(":smartcard"))
    ktlint(libs.ktlint.cli) {
        attributes {
            attribute(Bundling.BUNDLING_ATTRIBUTE, objects.named(Bundling.EXTERNAL))
        }
    }
}

val ktlintSourceFile =
    listOf(
        "**/src/**/*.kt",
        "**.kts",
        "!**/build/**",
    )

val ktlintCheck by tasks.registering(JavaExec::class) {
    group = LifecycleBasePlugin.VERIFICATION_GROUP
    description = "Check Kotlin code style"
    classpath = ktlint
    mainClass.set("com.pinterest.ktlint.Main")
    args(ktlintSourceFile)
}

tasks.register<JavaExec>("ktlintFormat") {
    group = LifecycleBasePlugin.VERIFICATION_GROUP
    description = "Check Kotlin code style and format"
    classpath = ktlint
    mainClass.set("com.pinterest.ktlint.Main")
    jvmArgs("--add-opens=java.base/java.lang=ALL-UNNAMED")
    args(
        "-F",
        *ktlintSourceFile.toTypedArray(),
    )
}
