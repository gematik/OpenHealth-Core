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

# How to Contribute to this Project

## Reporting Issues

When reporting an issue, please adhere to the following template for clarity and efficiency:
1. Bug Description: Clearly outline the problem.
2. Steps to Reproduce: Provide precise instructions to replicate the issue.
3. Optional: Include relevant code snippets.
4. OS and Architecture: Provide the version and architecture of the system where the problem occurred (e.g., Windows 11 x64, iOS 17.4.1, etc.).
5. Toolchain Details: Specify versions (e.g., Node.js, Java, etc.).
6. Library Version: Mention the version of this library involved.

## Submitting Merge Requests/Pull Requests

Ensure your Merge/Pull Request (MR/PR) includes:
1. Summary of Changes: A concise description of the updates or fixes being proposed.
2. Additional Context: Any relevant information, motivations, or dependencies that reviewers need to consider.

## Reviewing Changes (To be done by automation)

Ensure all the following pre-requirements are done:
1. Check `TODOs` are included with the provided ticket
2. Check `FIXMEs` are not included
3. Check for breaking API declaration changes:
    - Minor/Patch: All generated `.api` files must not remove or modify existing APIs
    - Major: Breaking changes must be documented in the `CHANGELOG.md`

# Repository Guidelines

## Code Style

Formatting:
```shell
cargo +nightly fmt --all
```

Linting:
```shell
cargo clippy --workspace --all-targets --all-features
```

## Handling TODOs

**TODOs**: Always associate `TODO` comments with a ticket in the following format:

`// TODO OPEN-1234: Description of the task or acceptable workaround.`

This ensures proper tracking and management of open `TODOs`.

## License

Annotate all files with the following command:

```shell
git diff -z --name-only origin/main HEAD -- ':(exclude)LICENSES/**' \
  | xargs -0 reuse annotate \
      --license Apache-2.0 \
      --copyright "gematik GmbH" \
      --template gematik \
      --copyright-prefix spdx-string \
      --merge-copyrights \
      --skip-unrecognised
```
