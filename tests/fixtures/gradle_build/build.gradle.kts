plugins {
    kotlin("jvm") version "2.0.21"
    application
}

group = "test.harbour"
version = "1.4.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    implementation(project(":model"))
    testImplementation(kotlin("test"))
}

kotlin {
    jvmToolchain(21)
}
