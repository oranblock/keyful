# ==============================================================================
# QVault 5 Mobile — R8 rules
# ==============================================================================
-keepattributes *Annotation*, InnerClasses, Signature, Exceptions

# ── BouncyCastle ─────────────────────────────────────────────────────────────
-keep class org.bouncycastle.crypto.** { *; }
-keep class org.bouncycastle.jce.** { *; }
# The JCE provider registers its algorithms (ISO9797Alg3Mac among them) by
# reflecting on these classes, so R8 cannot see the references.
-keep class org.bouncycastle.jcajce.** { *; }
-keep class org.bouncycastle.asn1.** { *; }
-dontwarn org.bouncycastle.**

# ── ICAO 9303 chip access (JMRTD + SCUBA) ────────────────────────────────────
-keep class org.jmrtd.** { *; }
-keep class net.sf.scuba.** { *; }
# Both also target desktop Java and reference classes Android does not ship.
-dontwarn org.jmrtd.**
-dontwarn net.sf.scuba.**
-dontwarn javax.smartcardio.**
-dontwarn java.awt.**
-dontwarn javax.imageio.**

# ── Vosk offline speech + speaker models (via JNA) ───────────────────────────
# JNA binds native functions and struct fields by name, through reflection and
# from native code, and neither AAR ships consumer rules. Renaming or stripping
# any of it makes the voice models fail to load, so QV6/QV7 could not open.
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }
-keep class org.vosk.** { *; }
-dontwarn com.sun.jna.**

# ── AndroidX & Compose ────────────────────────────────────────────────────────
-dontwarn kotlinx.coroutines.**
-dontwarn com.google.errorprone.annotations.**

# ── Strip all logging from release builds ────────────────────────────────────
# Release must never print card fingerprints, key fingerprints, or APDU traces.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
    public static int wtf(...);
}
