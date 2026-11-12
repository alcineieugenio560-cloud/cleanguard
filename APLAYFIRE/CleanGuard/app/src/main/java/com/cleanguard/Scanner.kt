package com.cleanguard

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest

data class Finding(val pkg: String, val label: String, val risk: Int, val reasons: List<String>)
data class Verdict(val level: Int, val reasons: List<String>)

object Scanner {
    private val TRUSTED = setOf("com.android.vending", "com.sec.android.app.samsungapps",
        "com.huawei.appmarket", "com.amazon.venezia", "com.xiaomi.mipicks")
    private val SENSITIVE = mapOf(
        "android.permission.SEND_SMS" to 2, "android.permission.READ_SMS" to 2,
        "android.permission.RECEIVE_SMS" to 1, "android.permission.READ_CALL_LOG" to 1,
        "android.permission.RECORD_AUDIO" to 1, "android.permission.READ_CONTACTS" to 1,
        "android.permission.SYSTEM_ALERT_WINDOW" to 2, "android.permission.REQUEST_INSTALL_PACKAGES" to 2,
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to 3, "android.permission.BIND_DEVICE_ADMIN" to 3)
    private const val EICAR = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    private val BAD_EXT = setOf("exe", "scr", "bat", "cmd", "vbs", "js", "jar", "msi", "com", "pif", "lnk")
    private val DOUBLE = Regex(".*\\.(jpe?g|png|gif|pdf|docx?|xlsx?|pptx?|txt|mp3|mp4|zip|rar)\\.(apk|exe|scr|bat|cmd|vbs|js|jar|lnk)$")

    fun sha256(f: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        f.inputStream().use { s ->
            val buf = ByteArray(8192)
            while (true) { val n = s.read(buf); if (n < 0) break; md.update(buf, 0, n) }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    fun blocklist(ctx: Context): Set<String> {
        val out = HashSet<String>()
        fun add(lines: List<String>) { for (l in lines) { val t = l.trim().lowercase(); if (t.isNotEmpty() && !t.startsWith("#")) out += t } }
        try { add(ctx.assets.open("blocklist.txt").bufferedReader().readLines()) } catch (_: Exception) {}
        try { val f = File(ctx.filesDir, "blocklist.txt"); if (f.exists()) add(f.readLines()) } catch (_: Exception) {}
        return out
    }

    private fun installer(ctx: Context, pkg: String): String? = try {
        if (Build.VERSION.SDK_INT >= 30) ctx.packageManager.getInstallSourceInfo(pkg).installingPackageName
        else @Suppress("DEPRECATION") ctx.packageManager.getInstallerPackageName(pkg)
    } catch (e: Exception) { null }

    private fun permRisk(perms: Set<String>, out: MutableList<String>): Int {
        var risk = 0
        for ((p, w) in SENSITIVE) if (p in perms) { risk += w; out += "Permissão: " + p.substringAfterLast('.') }
        if ("android.permission.SEND_SMS" in perms && "android.permission.READ_SMS" in perms) {
            risk += 3; out += "Combinação ler+enviar SMS (típica de trojans bancários)"
        }
        return risk
    }

    fun analyzePackage(ctx: Context, p: PackageInfo, bl: Set<String>): Finding? {
        val ai = p.applicationInfo ?: return null
        if (ai.flags and ApplicationInfo.FLAG_SYSTEM != 0 || p.packageName == ctx.packageName) return null
        var risk = 0
        val r = mutableListOf<String>()
        try { if (sha256(File(ai.sourceDir)) in bl) { risk += 10; r += "Hash conhecido de malware" } } catch (_: Exception) {}
        if (installer(ctx, p.packageName) !in TRUSTED) { risk += 2; r += "Instalado fora de loja confiável" }
        risk += permRisk(p.requestedPermissions?.toSet() ?: emptySet(), r)
        return if (risk >= 4) Finding(p.packageName, ctx.packageManager.getApplicationLabel(ai).toString(), risk, r) else null
    }

    fun scanApps(ctx: Context): List<Finding> {
        val bl = blocklist(ctx)
        @Suppress("DEPRECATION")
        val apps = ctx.packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        return apps.mapNotNull { analyzePackage(ctx, it, bl) }.sortedByDescending { it.risk }
    }

    fun analyzeFile(ctx: Context, f: File, bl: Set<String>): Verdict {
        var level = 0
        val r = mutableListOf<String>()
        val name = f.name.lowercase()
        val ext = f.extension.lowercase()
        if (DOUBLE.matches(name)) { level = 2; r += "Extensão dupla enganosa (disfarçado de documento ou mídia)" }
        else if (ext in BAD_EXT) { level = 1; r += "Arquivo executável incomum em celular" }
        if (ext == "apk") {
            val pi = try { @Suppress("DEPRECATION") ctx.packageManager.getPackageArchiveInfo(f.path, PackageManager.GET_PERMISSIONS) } catch (e: Exception) { null }
            val reasons = mutableListOf<String>()
            val risk = permRisk(pi?.requestedPermissions?.toSet() ?: emptySet(), reasons)
            level = maxOf(level, if (risk >= 4) 2 else 1)
            r += "APK baixado: instale apenas de fontes confiáveis"; r += reasons
        }
        if (f.length() in 1..200_000_000L) try {
            if (sha256(f) in bl) { level = 2; r += "Assinatura (hash) conhecida de malware" }
        } catch (_: Exception) {}
        if (f.length() in 1..2048L) try {
            if (f.readText(Charsets.ISO_8859_1).contains(EICAR)) { level = 2; r += "Arquivo de teste EICAR (inofensivo, usado para testar antivírus)" }
        } catch (_: Exception) {}
        return Verdict(level, r)
    }
}
