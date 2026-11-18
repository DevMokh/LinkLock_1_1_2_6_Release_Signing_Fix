import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.util.Properties

plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// Secrets may be supplied by CI environment variables or by the ignored local
// android/key.properties file. Environment variables take precedence.
val releaseSigningProperties = Properties().apply {
    val propertiesFile = rootProject.file("key.properties")
    if (propertiesFile.isFile) {
        propertiesFile.inputStream().use { load(it) }
    }
}

fun signingValue(environmentName: String, propertyName: String): String? =
    providers.environmentVariable(environmentName).orNull?.takeIf { it.isNotBlank() }
        ?: releaseSigningProperties.getProperty(propertyName)?.takeIf { it.isNotBlank() }

val releaseKeystorePath = signingValue("LINKLOCK_KEYSTORE_PATH", "storeFile")
val releaseStorePassword = signingValue("LINKLOCK_KEYSTORE_PASSWORD", "storePassword")
val releaseKeyAlias = signingValue("LINKLOCK_KEY_ALIAS", "keyAlias")
val releaseKeyPassword = signingValue("LINKLOCK_KEY_PASSWORD", "keyPassword")
val releaseKeystoreType = signingValue("LINKLOCK_KEYSTORE_TYPE", "storeType") ?: "JKS"
val releaseKeystoreFile = releaseKeystorePath?.let { project.file(it) }
val hasReleaseSigning = listOf(
    releaseKeystorePath,
    releaseStorePassword,
    releaseKeyAlias,
    releaseKeyPassword,
).all { !it.isNullOrBlank() } && releaseKeystoreFile?.isFile == true

android {
    namespace = "com.linklock.app"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "com.linklock.app"
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = releaseKeystoreFile
                storeType = releaseKeystoreType
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        release {
            // Never silently sign a release build with Android's public debug key.
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            } else {
                signingConfig = null
            }
        }
    }
}

// Fail clearly when someone asks for a distributable release without a private keystore.
tasks.configureEach {
    if (name == "packageRelease" || name == "packageReleaseBundle") {
        doFirst {
            if (!hasReleaseSigning) {
                throw GradleException(
                    "Release signing is not configured. Provide LINKLOCK_KEYSTORE_PATH, " +
                        "LINKLOCK_KEYSTORE_PASSWORD, LINKLOCK_KEY_ALIAS and LINKLOCK_KEY_PASSWORD " +
                        "as environment variables, or configure the ignored android/key.properties file. " +
                        "Use the debug build for local testing only."
                )
            }
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}
