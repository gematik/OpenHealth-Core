plugins {
    id("org.jetbrains.kotlin.multiplatform")
}

kotlin {
    jvm {
        withJava()
    }

    sourceSets {
        val commonMain by getting
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }

        val jvmMain by getting {
            dependencies {
                implementation(files("${rootProject.projectDir}/javalib/libasn1_jni.dylib"))
            }
        }
        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
    }

    jvmToolchain(17)
}

tasks.named<Test>("jvmTest") {
    useJUnitPlatform()
    dependsOn(":buildRustLibrary")

    systemProperty("java.library.path", "${rootProject.projectDir}/javalib")

    doFirst {
        println("java.library.path = ${System.getProperty("java.library.path")}")
    }
}