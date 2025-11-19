package de.gematik.openhealth.healthcard

import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.concurrent.atomic.AtomicBoolean

private const val LIBRARY_BASE_NAME = "health_card"

/**
 * Loads the UniFFI generated native library exactly once.
 *
 * We first try explicit configuration via the `healthcard.native.lib` system property
 * or the `HEALTHCARD_NATIVE_LIB` environment variable. When neither are provided we
 * fall back to the copy that Gradle places on the classpath (under `/native/<platform>`).
 */
object HealthCardNative {
    private val loaded = AtomicBoolean(false)
    private val platform = NativePlatform.detect()

    fun ensureLoaded() {
        if (loaded.get()) return
        synchronized(this) {
            if (loaded.get()) return
            val override = System.getProperty("healthcard.native.lib") ?: System.getenv("HEALTHCARD_NATIVE_LIB")
            if (!override.isNullOrBlank()) {
                loadFromFile(File(override))
                return
            }
            loadFromClasspath()
        }
    }

    private fun loadFromFile(file: File) {
        require(file.exists()) { "Native library ${file.absolutePath} does not exist." }
        System.setProperty("uniffi.component.health_card.libraryOverride", file.absolutePath)
        System.load(file.absolutePath)
        loaded.set(true)
    }

    private fun loadFromClasspath() {
        val resourcePath = "/native/${platform.resourceId}/${platform.libraryFileName(LIBRARY_BASE_NAME)}"
        val input = HealthCardNative::class.java.getResourceAsStream(resourcePath)
            ?: error(
                "Native trusted channel library not found at $resourcePath. " +
                    "Run :healthcard:copyHealthCardNativeLib to bundle it."
            )
        input.use {
            val tempFile = Files.createTempFile("health-card", platform.suffix())
            Files.copy(it, tempFile, StandardCopyOption.REPLACE_EXISTING)
            tempFile.toFile().deleteOnExit()
            System.setProperty("uniffi.component.health_card.libraryOverride", tempFile.toAbsolutePath().toString())
            System.load(tempFile.toAbsolutePath().toString())
            loaded.set(true)
        }
    }
}

private data class NativePlatform(
    val resourceId: String,
    private val prefix: String,
    private val ext: String,
) {
    fun libraryFileName(base: String): String = "$prefix${base}.$ext"

    fun suffix(): String = ".$ext"

    companion object {
        fun detect(): NativePlatform {
            val osName = System.getProperty("os.name").lowercase()
            val arch = System.getProperty("os.arch").lowercase()
            val osSegment = when {
                osName.contains("mac") || osName.contains("darwin") -> "darwin"
                osName.contains("win") -> "win32"
                osName.contains("nix") || osName.contains("nux") || osName.contains("linux") -> "linux"
                else -> error("Unsupported operating system: $osName")
            }
            val archSegment = when {
                arch.contains("aarch64") || arch.contains("arm64") -> "aarch64"
                arch.contains("64") -> "x86-64"
                arch == "x86" || arch == "i386" || arch == "i686" -> "x86"
                arch.startsWith("arm") -> "arm"
                else -> arch.replace(Regex("[^a-z0-9]+"), "-")
            }
            val (prefix, ext) = when (osSegment) {
                "win32" -> "" to "dll"
                "darwin" -> "lib" to "dylib"
                else -> "lib" to "so"
            }
            return NativePlatform("$osSegment-$archSegment", prefix, ext)
        }
    }
}
