package de.gematik.kmp.crypto

internal class NodeException(nodeError: dynamic) : Throwable(nodeError.message as String? ?: "Unknown error during digest")
