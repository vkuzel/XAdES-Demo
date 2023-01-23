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
    implementation("jakarta.xml.bind:jakarta.xml.bind-api:2.3.3")
    implementation("javax.xml.bind:jaxb-api:2.3.1")
    implementation("org.glassfish.jaxb:jaxb-runtime:2.3.6")
    implementation("org.bouncycastle:bcprov-jdk18on:1.72")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.72")
    implementation("org.bouncycastle:bcmail-jdk18on:1.72")
    testImplementation("org.junit.jupiter:junit-jupiter:5.9.2")
}

tasks.withType<Test> {
    useJUnitPlatform()
}

