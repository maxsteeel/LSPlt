val androidTargetSdkVersion by extra(36)
val androidMinSdkVersion by extra(21)
val androidBuildToolsVersion by extra("36.1.0")
val androidCompileSdkVersion by extra(36)
val androidNdkVersion by extra("29.0.14206865")
val androidCmakeVersion by extra("3.22.1+")

plugins {
    id("com.android.application") version "9.0.1" apply false
    id("com.android.library") version "9.0.1" apply false
}
