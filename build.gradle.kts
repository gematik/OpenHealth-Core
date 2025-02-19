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

    alias(libs.plugins.detekt) apply true

    id("org.jetbrains.kotlinx.binary-compatibility-validator") version "0.16.3"
//    id("org.jetbrains.dokka") version "2.0.0"
}

// subprojects {
//    apply(plugin = "org.jetbrains.dokka")
// }

tasks.register("licenseHeaderCheck") {
    val licenseTextRegex = "Copyright \\d{4} gematik GmbH".toRegex()

    val filesWithoutLicense =
        fileTree(".") {
            include("**/src/**/*.kt", "**/*.cpp", "**/*.hpp", "**/*.java", "**/*.ts", "**/*.js")
            exclude("**.*/*", "**/build/**", "**/dist/**", "**/generated/**", "**/node_modules/**")
        }.files.filter { file ->
            !file.readText().contains(licenseTextRegex)
        }

    doLast {
        if (filesWithoutLicense.isNotEmpty()) {
            filesWithoutLicense.forEach { file ->
                println("file://${file.absolutePath}: Missing or incorrect license header")
            }
            throw GradleException(
                "License check failed. Missing headers in ${filesWithoutLicense.size} files.",
            )
        }
    }
}

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

val ktlint by configurations.creating

dependencies {
    ktlint(libs.ktlint.cli) {
        attributes {
            attribute(Bundling.BUNDLING_ATTRIBUTE, objects.named(Bundling.EXTERNAL))
        }
    }
}

val ktlintCheck by tasks.registering(JavaExec::class) {
    group = LifecycleBasePlugin.VERIFICATION_GROUP
    description = "Check Kotlin code style"
    classpath = ktlint
    mainClass.set("com.pinterest.ktlint.Main")
    args(
        "**/src/**/*.kt",
        "**.kts",
        "!**/build/**",
    )
}

tasks.register<JavaExec>("ktlintFormat") {
    group = LifecycleBasePlugin.VERIFICATION_GROUP
    description = "Check Kotlin code style and format"
    classpath = ktlint
    mainClass.set("com.pinterest.ktlint.Main")
    jvmArgs("--add-opens=java.base/java.lang=ALL-UNNAMED")
    args(
        "-F",
        "**/src/**/*.kt",
        "**.kts",
        "!**/build/**",
    )
}
