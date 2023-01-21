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

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.72")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.72")
    implementation("org.bouncycastle:bcmail-jdk18on:1.72")
    implementation("org.apache.santuario:xmlsec:3.0.1")
    testImplementation("org.junit.jupiter:junit-jupiter:5.9.2")
}

tasks.withType<Test> {
    useJUnitPlatform()
}

