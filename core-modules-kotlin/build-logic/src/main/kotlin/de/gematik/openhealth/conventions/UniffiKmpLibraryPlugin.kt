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

import com.android.build.gradle.LibraryExtension
import com.vanniktech.maven.publish.MavenPublishBaseExtension
import org.gradle.api.GradleException
import org.gradle.api.JavaVersion
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
        ext.jnaVersion.convention("5.18.1")
        ext.publishToMavenCentral.convention(true)

        if (project.group.toString() == "unspecified") {
            project.group = "de.gematik.openhealth"
        }

        val generatedOutRoot = project.providers.environmentVariable("OUT_ROOT")
            .orElse(project.layout.buildDirectory.dir("generated/uniffi").map { it.asFile.absolutePath })
        val generatedKotlinDir = generatedOutRoot.map { "$it/kotlin" }.get()
        val generatedResourcesDir = generatedOutRoot.map { "$it/resources" }.get()
        val generatedJniLibsDir = generatedOutRoot.map { "$it/android-jni" }.get()

        project.afterEvaluate {
            val artifactId = ext.artifactId.orNull ?: throw GradleException("openHealthUniffiKmp.artifactId must be set")
            val androidNamespace =
                ext.androidNamespace.orNull ?: throw GradleException("openHealthUniffiKmp.androidNamespace must be set")
            val pomName = ext.pomName.orNull ?: throw GradleException("openHealthUniffiKmp.pomName must be set")
            val pomDescription =
                ext.pomDescription.orNull ?: throw GradleException("openHealthUniffiKmp.pomDescription must be set")
            val pomInceptionYear =
                ext.inceptionYear.orNull ?: throw GradleException("openHealthUniffiKmp.inceptionYear must be set")

            project.extensions.configure<LibraryExtension> {
                namespace = androidNamespace
                compileSdk = ext.compileSdk.get()

                defaultConfig.apply {
                    minSdk = ext.minSdk.get()
                    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
                    consumerProguardFiles("consumer-rules.pro")
                }

                compileOptions.apply {
                    sourceCompatibility = JavaVersion.VERSION_17
                    targetCompatibility = JavaVersion.VERSION_17
                }

                sourceSets.getByName("main").jniLibs.srcDir(generatedJniLibsDir)

                publishing.singleVariant("release") {
                    withSourcesJar()
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
        project.pluginManager.apply("com.android.library")
        project.pluginManager.apply("com.vanniktech.maven.publish")

        project.extensions.configure<KotlinMultiplatformExtension> {
            jvm()
            androidTarget {
                publishLibraryVariants("release")
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
    }
}
