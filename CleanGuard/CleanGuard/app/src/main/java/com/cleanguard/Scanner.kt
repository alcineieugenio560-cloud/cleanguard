package com.cleanguard

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest

data class Finding(val pkg: String, val label: String, val risk: Int, val reasons: List<String>)

object Scanner {
    private val TRUSTED = setOf(
        "com.android.vending", "com.sec.android.app.samsungapps",
        "com.huawei.appmarket", "com.amazon.venezia", "com.xiaomi.mipicks"
    )
    private val SENSITIVE = mapOf(
        "android.permission.SEND_SMS" to 2,
        "android.permission.READ_SMS" to 2,
        "android.permission.RECEIVE_SMS" to 1,
        "android.permission.READ_CALL_LOG" to 1,
        "android.permission.RECORD_AUDIO" to 1,
        "android.permission.READ_CONTACTS" to 1,
        "android.permission.SYSTEM_ALERT_WINDOW" to 2,
        "android.permission.REQUEST_INSTALL_PACKAGES" to 2,
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to 3,
        "android.permission.BIND_DEVICE_ADMIN" to 3
    )

    private fun sha256(f: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        f.inputStream().use { s ->
            val buf = ByteArray(8192)
            while (true) { val n = s.read(buf); if (n < 0) break; md.update(buf, 0, n) }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    private fun loadBlocklist(ctx: Context): Set<String> = try {
        ctx.assets.open("blocklist.txt").bufferedReader().readLines()
            .map { it.trim().lowercase() }.filter { it.isNotEmpty() && !it.startsWith("#") }.toSet()
    } catch (e: Exception) { emptySet() }

    private fun installer(ctx: Context, pkg: String): String? = try {
        if (Build.VERSION.SDK_INT >= 30) ctx.packageManager.getInstallSourceInfo(pkg).installingPackageName
        else @Suppress("DEPRECATION") ctx.packageManager.getInstallerPackageName(pkg)
    } catch (e: Exception) { null }

    fun scanApps(ctx: Context): List<Finding> {
        val pm = ctx.packageManager
        val blocklist = loadBlocklist(ctx)
        @Suppress("DEPRECATION")
        val apps: List<PackageInfo> = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        val out = mutableListOf<Finding>()
        for (p in apps) {
            val ai = p.applicationInfo ?: continue
            if (ai.flags and ApplicationInfo.FLAG_SYSTEM != 0) continue
            if (p.packageName == ctx.packageName) continue
            var risk = 0
            val reasons = mutableListOf<String>()
            try {
                if (sha256(File(ai.sourceDir)) in blocklist) { risk += 10; reasons += "HASH CONHECIDO COMO MALWARE" }
            } catch (_: Exception) {}
            if (installer(ctx, p.packageName) !in TRUSTED) { risk += 2; reasons += "Instalado fora de loja confiável" }
            val perms = p.requestedPermissions?.toSet() ?: emptySet()
            for ((perm, w) in SENSITIVE) if (perm in perms) {
                risk += w; reasons += "Permissão: " + perm.substringAfterLast('.')
            }
            if ("android.permission.SEND_SMS" in perms && "android.permission.READ_SMS" in perms) {
                risk += 3; reasons += "Combinação SMS ler+enviar (comum em trojans bancários)"
            }
            if (risk >= 4) out += Finding(p.packageName, pm.getApplicationLabel(ai).toString(), risk, reasons)
        }
        return out.sortedByDescending { it.risk }
    }
}
