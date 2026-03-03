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

import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.Property
import javax.inject.Inject

abstract class OpenHealthUniffiKmpExtension @Inject constructor(objects: ObjectFactory) {
    val artifactId: Property<String> = objects.property(String::class.java)
    val androidNamespace: Property<String> = objects.property(String::class.java)

    val pomName: Property<String> = objects.property(String::class.java)
    val pomDescription: Property<String> = objects.property(String::class.java)
    val inceptionYear: Property<String> = objects.property(String::class.java)

    val compileSdk: Property<Int> = objects.property(Int::class.java)
    val minSdk: Property<Int> = objects.property(Int::class.java)
    val jnaVersion: Property<String> = objects.property(String::class.java)
    val publishToMavenCentral: Property<Boolean> = objects.property(Boolean::class.java)
}

