<!-- Prefer PR titles like: OPEN-123: Short, imperative summary -->

## Summary
<!-- What does this PR do? Keep it short. -->

## Motivation / Context
<!-- Why is this change needed? Link ticket/issue(s). -->
Closes: <!-- OPEN-123 / GitHub issue link -->

## Changes
<!-- High-level list of changes (no implementation details). -->
- 

## How to Test
<!-- Exact commands / steps to verify. -->
- 

## Breaking Changes
<!-- API/behavior changes that require downstream updates. -->
- None

## Security / Privacy
<!-- Any security-sensitive changes? Confirm no secrets/PHI are included. -->
- 

## Checklist
- [ ] Tests added/updated where appropriate
- [ ] Rust: `cargo test` (or scoped `cargo test -p <crate>`)
- [ ] Rust (before pushing): `cargo +nightly fmt` and `cargo clippy --workspace --all-targets --no-default-features --features ci`
- [ ] Kotlin/JVM (if applicable): `./gradlew :healthcard:build` and/or `./gradlew test`
- [ ] Docs updated (`docs/`, `README.md`) if needed
- [ ] Release notes updated (`ReleaseNotes.md`) if user-facing change
