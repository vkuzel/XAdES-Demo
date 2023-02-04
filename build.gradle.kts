plugins {
    java
}

group = "com.vkuzel"
version = "1.0.0"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of("17"))
    }
}

sourceSets {
    main {
        java.srcDirs("src/generated/java")
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.glassfish.jaxb:jaxb-runtime:2.3.6")
    testImplementation("org.junit.jupiter:junit-jupiter:5.9.2")
}

tasks.withType<Test> {
    useJUnitPlatform()
}

