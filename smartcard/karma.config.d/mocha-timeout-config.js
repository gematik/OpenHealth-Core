// To increase the internal mocha test timeout (cannot be done from DSL)
// https://youtrack.jetbrains.com/issue/KT-56718#focus=Comments-27-6905607.0-0
config.set({
    client: {
        mocha: {
            // We put a large timeout here so we can adjust it in the tests themselves.
            timeout: 60000
        }
    }
});