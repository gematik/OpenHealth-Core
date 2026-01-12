<!--
SPDX-FileCopyrightText: Copyright 2025 - 2026 gematik GmbH

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

# Documentation Overview

This directory contains documentation for OpenHealth-Core, including interoperability notes, architecture documentation, and other project-specific guides.

## Architecture

Architecture-related documentation lives under `architecture/`:

- [`Architecture overview`](architecture/README.md) – Core modules, layering, data flows, and extension points.

## Interoperability

Interoperability-related notes live under `interop/`:

- [`JVM interoperability and debugging`](interop/jvm.md) – Debugging and interoperability notes for JVM targets (Java, Kotlin).

## Tooling

Developer tooling documentation lives under `tooling/`:

- [`APDU tools (recorder & replay)`](tooling/apdu-tools.md) – Record and replay APDU exchanges (PACE) for debugging and tests.

As additional documentation areas (e.g. architecture, APIs, deployment) are added under `docs/`, they should be organized into subdirectories and referenced from this overview.
