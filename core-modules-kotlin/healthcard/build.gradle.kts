import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.MapProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction
import org.gradle.internal.os.OperatingSystem
import org.gradle.kotlin.dsl.support.serviceOf
import org.gradle.process.ExecOperations
import java.io.File
import javax.inject.Inject

plugins {
    kotlin("jvm")
}

group = "de.gematik.openhealth.healthcard"

kotlin {
    jvmToolchain(21)
}

dependencies {
    implementation("net.java.dev.jna:jna:5.14.0")
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

val rustCrateDir = rootProject.layout.projectDirectory.dir("../core-modules/healthcard")
val uniffiConfigFile = rustCrateDir.file("uniffi.toml")
val crateName = "healthcard"
val crateLibName = crateName.replace("-", "_")
val os = OperatingSystem.current()
val cargoExecutableProvider = providers.systemProperty("healthcard.cargoPath")
    .orElse(providers.environmentVariable("CARGO"))
    .orElse(
        providers.provider {
            val cargoHome = System.getenv("CARGO_HOME")?.let(::File)
            val defaultHome = cargoHome ?: File(System.getProperty("user.home")).resolve(".cargo")
            defaultHome.resolve("bin/cargo").absolutePath
        }
    )
    .orElse("cargo")

fun determineResourceId(os: OperatingSystem): String {
    val arch = System.getProperty("os.arch").lowercase()
    val archSegment = when {
        arch.contains("aarch64") || arch.contains("arm64") -> "aarch64"
        arch.contains("64") -> "x86-64"
        arch == "x86" || arch == "i386" || arch == "i686" -> "x86"
        arch.startsWith("arm") -> "arm"
        else -> arch.replace(Regex("[^a-z0-9]+"), "-")
    }
    val osSegment = when {
        os.isMacOsX -> "darwin"
        os.isLinux -> "linux"
        os.isWindows -> "win32"
        else -> error("Unsupported OS: ${System.getProperty("os.name")}")
    }
    return "$osSegment-$archSegment"
}

val nativePlatformId = determineResourceId(os)

val nativeLibExtension = when {
    os.isMacOsX -> "dylib"
    os.isLinux -> "so"
    os.isWindows -> "dll"
    else -> error("Unsupported OS: ${System.getProperty("os.name")}")
}
val nativeLibPrefix = if (os.isWindows) "" else "lib"
val nativeLibraryFileName = "${nativeLibPrefix}${crateLibName}.${nativeLibExtension}"

val cargoTargetDir = layout.buildDirectory.dir("cargo")
// Use debug profile so we can step through Rust code more easily
val rustLibrary = cargoTargetDir.map { it.dir("debug").file(nativeLibraryFileName) }
val generatedKotlinDir = layout.buildDirectory.dir("generated/uniffi/kotlin")
val generatedResourcesDir = layout.buildDirectory.dir("generated/uniffi/resources")
val nativeResourceDir = layout.buildDirectory.dir("generated/uniffi/resources/$nativePlatformId")

val uniffiVersion = "0.30.0"

val uniffiCliManifest = objects.fileProperty().also { property ->
    val overridePath = System.getenv("UNIFFI_CLI_MANIFEST")?.takeIf { it.isNotBlank() }
    if (overridePath != null) {
        val manifest = file(overridePath)
        if (!manifest.isFile) {
            throw GradleException("UNIFFI_CLI_MANIFEST does not point to a file: $overridePath")
        }
        property.set(manifest)
        return@also
    }

    val cargoHome = System.getenv("CARGO_HOME")?.let(::File) ?: File(System.getProperty("user.home")).resolve(".cargo")
    val registrySrc = cargoHome.resolve("registry/src")

    val manifest = registrySrc
        .walkTopDown()
        .maxDepth(3)
        .firstOrNull { it.isFile && it.name == "Cargo.toml" && it.parentFile?.name == "uniffi-$uniffiVersion" }
        ?: throw GradleException(
            "Could not locate uniffi-$uniffiVersion sources under ${registrySrc.absolutePath}. " +
                "Build the Rust crate once so Cargo downloads it or set UNIFFI_CLI_MANIFEST explicitly."
        )
    property.set(manifest)
}

val cargoEnvironment = run {
    val cargoHome = System.getenv("CARGO_HOME")?.let(::File)
    val defaultHome = cargoHome ?: File(System.getProperty("user.home")).resolve(".cargo")
    val cargoBinDir = defaultHome.resolve("bin")
    val currentPath = System.getenv("PATH") ?: ""
    val pathWithCargo = if (cargoBinDir.isDirectory) {
        cargoBinDir.absolutePath + File.pathSeparator + currentPath
    } else {
        currentPath
    }

    mapOf(
        "CARGO_TARGET_DIR" to cargoTargetDir.get().asFile.absolutePath,
        "PATH" to pathWithCargo
    )
}

val buildHealthCardRust = tasks.register<Exec>("buildHealthCardRust") {
    workingDir = rustCrateDir.asFile
    environment(cargoEnvironment)
    commandLine(
        cargoExecutableProvider.get(),
        "build",
        "--manifest-path",
        rustCrateDir.file("Cargo.toml").asFile.absolutePath
    )
    inputs.dir(rustCrateDir)
    outputs.file(rustLibrary)
}

val generateUniFfiBindings = tasks.register("generateHealthCardUniFfiBindings") {
    dependsOn(buildHealthCardRust)
    inputs.file(rustLibrary)
    outputs.dir(generatedKotlinDir)
    doLast {
        val libFile = rustLibrary.get().asFile
        if (!libFile.exists()) {
            throw GradleException(
                "Rust library not found at ${libFile.absolutePath}. " +
                    "Did :healthcard:buildHealthCardRust succeed?"
            )
        }
        generatedKotlinDir.get().asFile.apply {
            deleteRecursively()
            mkdirs()
        }
        val execOperations = project.serviceOf<ExecOperations>()
        execOperations.exec {
            environment(cargoEnvironment)
            commandLine(
                cargoExecutableProvider.get(),
                "run",
                "--manifest-path",
                uniffiCliManifest.get().asFile.absolutePath,
                "--quiet",
                "--features",
                "cli",
                "--bin",
                "uniffi-bindgen",
                "--",
                "generate",
                "--config",
                uniffiConfigFile.asFile.absolutePath,
                "--library",
                libFile.absolutePath,
                "--language",
                "kotlin",
                "--out-dir",
                generatedKotlinDir.get().asFile.absolutePath,
                "--no-format",
            )
        }
    }
}

val copyHealthCardNativeLib = tasks.register<Copy>("copyHealthCardNativeLib") {
    dependsOn(buildHealthCardRust)
    val builtLib = rustLibrary.get().asFile
    inputs.file(builtLib)
    from(builtLib)
    into(nativeResourceDir)
}

sourceSets {
    val main by getting {
        kotlin.srcDir(generatedKotlinDir)
        resources.srcDir(generatedResourcesDir)
    }
}

tasks.named("compileKotlin") {
    dependsOn(generateUniFfiBindings)
}

tasks.named("processResources") {
    dependsOn(copyHealthCardNativeLib)
}
