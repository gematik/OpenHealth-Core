package de.gematik.kmp.crypto

internal class NodeException(
    nodeError: dynamic,
) : Throwable(nodeError.message as String? ?: "Unknown error during digest")

fun <T> runNodeCatching(block: () -> T): T {
    try {
        return block()
    } catch (e: dynamic) {
        when (e) {
            is IllegalArgumentException -> throw e
            is IllegalStateException -> throw e
            else -> throw NodeException(e)
        }
    }
}