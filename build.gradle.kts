plugins {
    kotlin("jvm") version "2.0.21"
    id("com.gradleup.shadow") version "9.0.0-beta12"
}

group = "io.burpmcp.ultimate"
version = "0.2.0"

repositories {
    mavenCentral()
}

val montoyaVersion: String by project
val jacksonVersion: String by project
val kotlinxCoroutinesVersion: String by project
val junitVersion: String by project

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:$montoyaVersion")
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:$jacksonVersion")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:$kotlinxCoroutinesVersion")

    testImplementation("net.portswigger.burp.extensions:montoya-api:$montoyaVersion")
    testImplementation("org.junit.jupiter:junit-jupiter:$junitVersion")
    testImplementation("org.jetbrains.kotlin:kotlin-test:2.0.21")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(21)) }
}

kotlin { jvmToolchain(21) }

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = false
    }
}

tasks.shadowJar {
    archiveClassifier.set("")
    archiveBaseName.set("burp-mcp-ultimate")
    mergeServiceFiles()
    relocate("com.fasterxml.jackson", "io.burpmcp.shaded.jackson")
    relocate("kotlinx.coroutines",   "io.burpmcp.shaded.coroutines")
    manifest {
        attributes(
            "Implementation-Title"   to "burp-mcp-ultimate",
            "Implementation-Version" to project.version.toString(),
            "Implementation-Vendor"  to "io.burpmcp.ultimate",
        )
    }
}

tasks.jar { enabled = false }
tasks.build { dependsOn(tasks.shadowJar) }
