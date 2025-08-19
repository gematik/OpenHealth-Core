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

TODO

## Handling TODOs

**TODOs**: Always associate `TODO` comments with a ticket in the following format:

`// TODO OPEN-1234: Description of the task or acceptable workaround.`

This ensures proper tracking and management of open `TODOs`.