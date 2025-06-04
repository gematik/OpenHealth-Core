plugins {
    kotlin("multiplatform") version "1.9.21" apply false
}

allprojects {
    group = "org.example"
    version = "1.0-SNAPSHOT"

    repositories {
        mavenCentral()
    }
}

tasks.register<Exec>("buildRustLibrary") {
    workingDir = file("${projectDir}/asn1-jni")

    commandLine("${System.getProperty("user.home")}/.cargo/bin/cargo",
        "build", "--release", "--target", "aarch64-apple-darwin")

    doFirst {
        file("${projectDir}/target/${"aarch64-apple-darwin"}/release").mkdirs()
    }

    doLast {
        project.ext.set("rustTarget", "aarch64-apple-darwin")
    }

}

