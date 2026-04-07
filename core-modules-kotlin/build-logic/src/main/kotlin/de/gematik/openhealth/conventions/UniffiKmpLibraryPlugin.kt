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

package de.gematik.openhealth.conventions

import com.android.build.api.dsl.androidLibrary
import com.android.build.api.variant.KotlinMultiplatformAndroidComponentsExtension
import com.vanniktech.maven.publish.MavenPublishBaseExtension
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.tasks.testing.Test
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.withType
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension

class UniffiKmpLibraryPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        val ext = project.extensions.create("openHealthUniffiKmp", OpenHealthUniffiKmpExtension::class.java)
        ext.compileSdk.convention(36)
        ext.minSdk.convention(24)
        ext.jnaVersion.convention("5.14.0")
        ext.publishToMavenCentral.convention(true)

        val publicationGroup = project.rootProject.group.toString()
            .takeIf { it != "unspecified" }
            ?: "de.gematik.openhealth"
        project.group = publicationGroup

        val generatedOutRoot = project.providers.environmentVariable("OUT_ROOT")
            .orElse(project.layout.buildDirectory.dir("generated/uniffi").map { it.asFile.absolutePath })
        val generatedKotlinDir = generatedOutRoot.map { "$it/kotlin" }.get()
        val generatedResourcesDir = generatedOutRoot.map { "$it/resources" }.get()
        val generatedJniLibsDir = generatedOutRoot.map { "$it/android-jni" }.get()
        val generatedKotlinDirFile = project.file(generatedKotlinDir)
        val generatedResourcesDirFile = project.file(generatedResourcesDir)
        val generatedJniLibsDirFile = project.file(generatedJniLibsDir)

        val validateJvmGeneratedBindings = project.tasks.register("validateJvmGeneratedBindings") {
            doLast {
                if (!generatedKotlinDirFile.isDirectory) {
                    throw GradleException(
                        "Generated Kotlin bindings are missing at `${generatedKotlinDirFile.absolutePath}`. " +
                            "Run `just kotlin-bindings-generate <module> <platform> <arch> <library_file> [profile]` first.",
                    )
                }

                if (!generatedResourcesDirFile.isDirectory || generatedResourcesDirFile.walkTopDown().none { it.isFile }) {
                    throw GradleException(
                        "Generated JVM native resources are missing at `${generatedResourcesDirFile.absolutePath}`. " +
                            "Run `just kotlin-bindings-generate <module> <platform> <arch> <library_file> [profile]` first.",
                    )
                }
            }
        }

        val validateAndroidGeneratedBindings = project.tasks.register("validateAndroidGeneratedBindings") {
            doLast {
                if (!generatedKotlinDirFile.isDirectory) {
                    throw GradleException(
                        "Generated Kotlin bindings are missing at `${generatedKotlinDirFile.absolutePath}`. " +
                            "Run `just kotlin-bindings-generate <module> <platform> <arch> <library_file> [profile]` first.",
                    )
                }

                if (!generatedJniLibsDirFile.isDirectory || generatedJniLibsDirFile.walkTopDown().none { it.isFile && it.extension == "so" }) {
                    throw GradleException(
                        "Generated Android JNI libraries are missing at `${generatedJniLibsDirFile.absolutePath}`. " +
                            "Run `just kotlin-bindings-generate-android <module> [profile]` first.",
                    )
                }
            }
        }

        project.afterEvaluate {
            val artifactId = ext.artifactId.orNull ?: throw GradleException("openHealthUniffiKmp.artifactId must be set")
            val androidNamespace =
                ext.androidNamespace.orNull ?: throw GradleException("openHealthUniffiKmp.androidNamespace must be set")
            val pomName = ext.pomName.orNull ?: throw GradleException("openHealthUniffiKmp.pomName must be set")
            val pomDescription =
                ext.pomDescription.orNull ?: throw GradleException("openHealthUniffiKmp.pomDescription must be set")
            val pomInceptionYear =
                ext.inceptionYear.orNull ?: throw GradleException("openHealthUniffiKmp.inceptionYear must be set")

            project.extensions.configure<KotlinMultiplatformExtension> {
                androidLibrary {
                    namespace = androidNamespace
                    compileSdk = ext.compileSdk.get()
                    minSdk = ext.minSdk.get()
                }
            }

            project.extensions.configure<KotlinMultiplatformAndroidComponentsExtension> {
                onVariants { variant ->
                    variant.sources.jniLibs?.addStaticSourceDirectory(generatedJniLibsDir)
                }
            }

            project.extensions.configure<MavenPublishBaseExtension> {
                if (ext.publishToMavenCentral.get()) {
                    publishToMavenCentral()
                }

                coordinates(artifactId = artifactId)

                pom {
                    name.set(pomName)
                    description.set(pomDescription)
                    inceptionYear.set(pomInceptionYear)
                    url.set("https://github.com/gematik/OpenHealth-Core")

                    licenses {
                        license {
                            name.set("Apache 2.0")
                            url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                            distribution.set("repo")
                        }
                    }

                    developers {
                        developer {
                            name.set("gematik GmbH")
                            url.set("https://github.com/gematik")
                        }
                    }

                    scm {
                        url.set("https://github.com/gematik/OpenHealth-Core")
                        connection.set("scm:git:https://github.com/gematik/OpenHealth-Core.git")
                        developerConnection.set("scm:git:https://github.com/gematik/OpenHealth-Core.git")
                    }
                }
            }
        }

        project.pluginManager.apply("org.jetbrains.kotlin.multiplatform")
        project.pluginManager.apply("com.android.kotlin.multiplatform.library")
        project.pluginManager.apply("com.vanniktech.maven.publish")

        project.extensions.configure<KotlinMultiplatformExtension> {
            jvm()
            androidLibrary {
                withDeviceTest {
                    instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
                }
            }
            jvmToolchain(21)

            sourceSets.getByName("jvmMain").apply {
                kotlin.srcDir(generatedKotlinDir)
                resources.srcDir(generatedResourcesDir)
            }
            sourceSets.getByName("androidMain").apply {
                kotlin.srcDir(generatedKotlinDir)
            }
        }

        project.dependencies.add("jvmMainImplementation", "net.java.dev.jna:jna:${ext.jnaVersion.get()}")
        project.dependencies.add("androidMainImplementation", "net.java.dev.jna:jna:${ext.jnaVersion.get()}@aar")

        project.tasks.withType<Test>().configureEach {
            useJUnitPlatform()
        }

        project.tasks.matching { it.name == "compileTestKotlinJvm" || it.name == "jvmTest" }.configureEach {
            onlyIf { project.file(generatedKotlinDir).exists() }
        }

        project.tasks.matching {
            it.name in setOf(
                "publishJvmPublicationToMavenLocal",
                "publishJvmPublicationToMavenCentralRepository",
            )
        }.configureEach {
            dependsOn(validateJvmGeneratedBindings)
        }

        project.tasks.matching {
            it.name in setOf(
                "publishAndroidPublicationToMavenLocal",
                "publishAndroidPublicationToMavenCentralRepository",
            )
        }.configureEach {
            dependsOn(validateAndroidGeneratedBindings)
        }

        project.tasks.matching {
            it.name in setOf(
                "publishKotlinMultiplatformPublicationToMavenLocal",
                "publishKotlinMultiplatformPublicationToMavenCentralRepository",
            )
        }.configureEach {
            dependsOn(validateJvmGeneratedBindings, validateAndroidGeneratedBindings)
        }
    }
}
