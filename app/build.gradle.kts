plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val dohUrl = System.getenv("ECH_DOH_URL") ?: "https://YOUR-DOH-HOST.example/dns-query"

android {
    namespace = "com.anglesgirl.echh3probe"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.anglesgirl.echh3probe"
        minSdk = 24
        targetSdk = 36
        versionCode = System.getenv("GITHUB_RUN_NUMBER")?.toIntOrNull() ?: 1
        versionName = "1.0." + (System.getenv("GITHUB_RUN_NUMBER") ?: "1")
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a") }
        buildConfigField("String", "DOH_URL", "\"$dohUrl\"")
    }

    buildFeatures { buildConfig = true }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    buildTypes {
        getByName("release") { isMinifyEnabled = false }
    }
}
