<!--
SPDX-FileCopyrightText: Copyright 2026 gematik GmbH

SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*******

For additional notes and disclaimer from gematik and in case of changes by gematik,
find details in the "Readme" file.
-->

# Kotlin bindings (core-modules-kotlin)

This directory contains Kotlin Multiplatform (KMP) bindings for Rust core modules generated via UniFFI.

## Generated artifact layout (`OUT_ROOT`)

Gradle consumes pre-generated outputs from `OUT_ROOT` (defaults to `build/generated/uniffi` inside each Kotlin module):

- Kotlin sources: `${OUT_ROOT}/kotlin`
- Native library resources (JNA): `${OUT_ROOT}/resources/<resource-id>/`
- Android JNI libs (optional): `${OUT_ROOT}/android-jni/`

## Adding a new Rust-backed binding module

1) Create a new Gradle subproject under `core-modules-kotlin/<module>`.
2) Add `include(":<module>")` to `core-modules-kotlin/settings.gradle.kts`.
3) In `core-modules-kotlin/<module>/build.gradle.kts`, apply the convention plugin:

```kotlin
plugins {
    id("de.gematik.openhealth.uniffi-kmp-library")
}

openHealthUniffiKmp {
    artifactId.set("<module>")
    androidNamespace.set("de.gematik.openhealth.<module>")
    pomName.set("OpenHealth <Module>")
    pomDescription.set("...")
    inceptionYear.set("2026")
}
```

4) Add module entries where required:
   - `just` recipes: new module name in `just/kotlin.just` (and `just/swift.just` if Swift is required).
   - CI workflow: add matrix entries in `.github/workflows/release-bindings.yml`.

