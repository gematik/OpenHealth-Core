#!/bin/sh

echo "Running pre-commit hook"

echo "Running lint checks"
if ! ./gradlew detekt ktlintCheck; then
  echo "Lint errors detected. Commit aborted."
  exit 1
fi
echo "Lint checks passed"