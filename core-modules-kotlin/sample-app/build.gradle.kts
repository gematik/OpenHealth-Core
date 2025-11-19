plugins {
    kotlin("jvm")
    application
}

group = "de.gematik.openhealth.sample"

kotlin {
    jvmToolchain(23)
    compilerOptions {
        freeCompilerArgs.add("-Xadd-modules=java.smartcardio")
    }
}

dependencies {
    implementation(project(":healthcard"))
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

application {
    mainClass = "de.gematik.openhealth.sample.TrustedChannelCliKt"
    applicationDefaultJvmArgs += listOf("--add-modules=java.smartcardio")
}
