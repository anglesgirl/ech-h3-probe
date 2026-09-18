// 必须显式导入 File：Kotlin DSL 脚本里 `java` 指向 JavaPluginExtension，
// 直接写 java.io.File 会报 Unresolved reference: io（实测栽过）
import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val dohUrl = System.getenv("ECH_DOH_URL") ?: "https://tgxjjdszvu.cloudflare-gateway.com/dns-query"

// CI 注入固定签名。不固定的话每个 runner 都会现生成一个 debug.keystore，
// 于是每轮构建签名都不同 → 用户无法覆盖安装（实测表现：每次都提示"签名不一致"）。
val pinnedKeystore = System.getenv("PROBE_KEYSTORE")?.let { File(it) }?.takeIf { it.exists() }

android {
    namespace = "com.anglesgirl.echh3probe"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.anglesgirl.echh3probe"
        minSdk = 24
        targetSdk = 36
        // 必须走 -P 属性：System.getenv 不在 Gradle 配置缓存的追踪范围内，
        // 缓存会复用上一轮的版本号 → 实测每轮都编出同一个 1.0.7。
        versionCode = providers.gradleProperty("appVersionCode").orNull?.toIntOrNull() ?: 1
        versionName = providers.gradleProperty("appVersionName").orNull ?: "1.0.1"
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a") }
        buildConfigField("String", "DOH_URL", "\"$dohUrl\"")
    }

    buildFeatures { buildConfig = true }

    signingConfigs {
        if (pinnedKeystore != null) {
            getByName("debug") {
                storeFile = pinnedKeystore
                storePassword = System.getenv("PROBE_STORE_PASS")
                keyAlias = System.getenv("PROBE_KEY_ALIAS") ?: "probe"
                keyPassword = System.getenv("PROBE_KEY_PASS") ?: System.getenv("PROBE_STORE_PASS")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    buildTypes {
        getByName("release") { isMinifyEnabled = false }
    }
}
