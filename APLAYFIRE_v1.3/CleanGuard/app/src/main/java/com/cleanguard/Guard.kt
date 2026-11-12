
package com.cleanguard

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Icon
import android.net.Uri
import android.os.Build
import android.os.Environment
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.URL
import javax.net.ssl.HttpsURLConnection

object ThreatLog {

    private fun sp(c: Context) =
        c.getSharedPreferences("guard", Context.MODE_PRIVATE)

    fun enabled(c: Context) = sp(c).getBoolean("on", false)

    fun setEnabled(c: Context, v: Boolean) =
        sp(c).edit().putBoolean("on", v).apply()

    fun setting(c: Context, k: String, d: Boolean) =
        sp(c).getBoolean("s_$k", d)

    fun setSetting(c: Context, k: String, v: Boolean) =
        sp(c).edit().putBoolean("s_$k", v).apply()

    fun lang(c: Context): String =
        sp(c).getString("lang", "pt") ?: "pt"

    fun setLang(c: Context, l: String) =
        sp(c).edit().putString("lang", l).apply()

    fun clear(c: Context) {
        sp(c).edit()
            .putString("log", "[]")
            .putInt("threats", 0)
            .apply()
    }

    @Synchronized
    fun checked(c: Context) {
        sp(c).edit()
            .putInt("files", sp(c).getInt("files", 0) + 1)
            .apply()
    }

    @Synchronized
    fun add(
        c: Context,
        kind: String,
        name: String,
        target: String,
        level: Int,
        reasons: List<String>
    ) {
        val o = JSONObject()
            .put("t", System.currentTimeMillis())
            .put("k", kind)
            .put("n", name)
            .put("p", target)
            .put("l", level)
            .put("w", JSONArray(reasons))

        val old = JSONArray(sp(c).getString("log", "[]"))
        val arr = JSONArray().put(o)

        for (i in 0 until minOf(old.length(), 49)) {
            arr.put(old.get(i))
        }

        sp(c).edit()
            .putString("log", arr.toString())
            .putInt("threats", sp(c).getInt("threats", 0) + 1)
            .apply()
    }

    fun json(c: Context): JSONObject =
        JSONObject()
            .put("on", enabled(c))
            .put("files", sp(c).getInt("files", 0))
            .put("threats", sp(c).getInt("threats", 0))
            .put("ev", JSONArray(sp(c).getString("log", "[]")))
}

object Tr {

    private val M = mapOf(
        "Download perigoso: " to listOf(
            "Download perigoso: ",
            "Dangerous download: ",
            "Descarga peligrosa: "
        ),

        "Download suspeito: " to listOf(
            "Download suspeito: ",
            "Suspicious download: ",
            "Descarga sospechosa: "
        ),

        "App suspeito instalado: " to listOf(
            "App suspeito instalado: ",
            "Suspicious app installed: ",
            "App sospechosa instalada: "
        ),

        "Apagar arquivo" to listOf(
            "Apagar arquivo",
            "Delete file",
            "Borrar archivo"
        ),

        "Desinstalar" to listOf(
            "Desinstalar",
            "Uninstall",
            "Desinstalar"
        ),

        "Alertas de ameaça" to listOf(
            "Alertas de ameaça",
            "Threat alerts",
            "Alertas de amenazas"
        ),

        "Proteção ativa" to listOf(
            "Proteção ativa",
            "Active protection",
            "Protección activa"
        ),

        "APLAYFIRE protegendo" to listOf(
            "APLAYFIRE protegendo",
            "APLAYFIRE is protecting",
            "APLAYFIRE protegiendo"
        ),

        "Vigiando downloads e novos apps" to listOf(
            "Vigiando downloads e novos apps",
            "Watching downloads and new apps",
            "Vigilando descargas y apps nuevas"
        )
    )

    fun t(c: Context, k: String): String {
        val i = when (ThreatLog.lang(c)) {
            "en" -> 1
            "es" -> 2
            else -> 0
        }

        return M[k]?.get(i) ?: k
    }
}

object Notifier {

    private const val CH = "guard"
    private const val CH2 = "status"

    fun channels(c: Context) {
        if (Build.VERSION.SDK_INT < 26) return

        val nm = c.getSystemService(NotificationManager::class.java)

        nm.createNotificationChannel(
            NotificationChannel(
                CH,
                Tr.t(c, "Alertas de ameaça"),
                NotificationManager.IMPORTANCE_HIGH
            )
        )

        nm.createNotificationChannel(
            NotificationChannel(
                CH2,
                Tr.t(c, "Proteção ativa"),
                NotificationManager.IMPORTANCE_MIN
            )
        )
    }

    @Suppress("DEPRECATION")
    private fun builder(c: Context, ch: String): Notification.Builder =
        if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(c, ch)
        } else {
            Notification.Builder(c)
        }

    private fun open(c: Context) =
        PendingIntent.getActivity(
            c,
            0,
            Intent(c, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

    fun ongoing(c: Context): Notification =
        builder(c, CH2)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentTitle(Tr.t(c, "APLAYFIRE protegendo"))
            .setContentText(Tr.t(c, "Vigiando downloads e novos apps"))
            .setContentIntent(open(c))
            .setOngoing(true)
            .build()

    fun threat(
        c: Context,
        id: Int,
        title: String,
        text: String,
        action: Notification.Action
    ) {
        val b = builder(c, CH)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText(text.lines().first())
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(open(c))
            .setAutoCancel(true)
            .addAction(action)

        try {
            c.getSystemService(NotificationManager::class.java)
                .notify(id, b.build())
        } catch (_: Exception) {
        }
    }

    fun deleteAction(
        c: Context,
        path: String,
        id: Int
    ): Notification.Action {

        val i = Intent(c, ActionReceiver::class.java)
            .putExtra("path", path)
            .putExtra("id", id)

        val pi = PendingIntent.getBroadcast(
            c,
            id,
            i,
            PendingIntent.FLAG_IMMUTABLE or
                PendingIntent.FLAG_UPDATE_CURRENT
        )

        return Notification.Action.Builder(
            Icon.createWithResource(
                c,
                android.R.drawable.ic_menu_delete
            ),
            Tr.t(c, "Apagar arquivo"),
            pi
        ).build()
    }

    fun uninstallAction(
        c: Context,
        pkg: String,
        id: Int
    ): Notification.Action {

        val i = Intent(
            Intent.ACTION_DELETE,
            Uri.parse("package:$pkg")
        ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

        val pi = PendingIntent.getActivity(
            c,
            id,
            i,
            PendingIntent.FLAG_IMMUTABLE or
                PendingIntent.FLAG_UPDATE_CURRENT
        )

        return Notification.Action.Builder(
            Icon.createWithResource(
                c,
                android.R.drawable.ic_menu_delete
            ),
            Tr.t(c, "Desinstalar"),
            pi
        ).build()
    }
}

object Guard {

    fun safeDelete(path: String): Boolean {
        return try {
            val f = File(path)
            val root = Environment
                .getExternalStorageDirectory()
                .canonicalPath

            f.canonicalPath.startsWith("$root${File.separator}") &&
                f.delete()
        } catch (_: Exception) {
            false
        }
    }

    fun checkFile(c: Context, f: File) {
        if (!f.isFile) return

        ThreatLog.checked(c)

        val v = Scanner.analyzeFile(
            c,
            f,
            Scanner.blocklist(c)
        )

        if (v.level == 0) return

        val id = f.path.hashCode()

        ThreatLog.add(
            c,
            "file",
            f.name,
            f.path,
            v.level,
            v.reasons
        )

        Notifier.threat(
            c,
            id,
            Tr.t(
                c,
                if (v.level >= 2)
                    "Download perigoso: "
                else
                    "Download suspeito: "
            ) + f.name,
            v.reasons.joinToString("\n• ", "• "),
            Notifier.deleteAction(c, f.path, id)
        )
    }

    fun checkPackage(c: Context, pkg: String) {
        try {
            @Suppress("DEPRECATION")
            val p = c.packageManager.getPackageInfo(
                pkg,
                PackageManager.GET_PERMISSIONS
            )

            val f = Scanner.analyzePackage(
                c,
                p,
                Scanner.blocklist(c)
            ) ?: return

            val lvl = if (f.risk >= 8) 2 else 1

            ThreatLog.add(
                c,
                "app",
                f.label,
                f.pkg,
                lvl,
                f.reasons
            )

            Notifier.threat(
                c,
                pkg.hashCode(),
                Tr.t(c, "App suspeito instalado: ") + f.label,
                f.reasons.joinToString("\n• ", "• "),
                Notifier.uninstallAction(
                    c,
                    pkg,
                    pkg.hashCode()
                )
            )

        } catch (_: Exception) {
        }
    }
}

object SignatureUpdater {

    // Substitua pela URL RAW do seu blocklist.txt no GitHub.
    const val SIG_URL =
        "https://raw.githubusercontent.com/SEU_USUARIO/SEU_REPO/main/blocklist.txt"

    private val HEX = Regex("[0-9a-f]{64}")

    fun update(c: Context): Int {
        if (SIG_URL.contains("SEU_USUARIO")) return -1

        return try {
            val con = URL(SIG_URL)
                .openConnection() as HttpsURLConnection

            con.connectTimeout = 10000
            con.readTimeout = 15000

            val hashes = con.inputStream.bufferedReader().useLines { seq ->
                seq.map { x -> x.trim().lowercase() }
                    .filter { x -> HEX.matches(x) }
                    .take(500000)
                    .toList()
            }

            File(c.filesDir, "blocklist.txt")
                .writeText(hashes.joinToString("\n"))

            hashes.size

        } catch (_: Exception) {
            -2
        }
    }
}
