plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
android {
    namespace = "com.cleanguard"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.cleanguard"
        minSdk = 24
        targetSdk = 34
        versionCode = 3
        versionName = "1.3"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}
