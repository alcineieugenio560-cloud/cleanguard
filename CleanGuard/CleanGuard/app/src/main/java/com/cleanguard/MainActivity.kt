package com.cleanguard

import android.app.Activity
import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.StatFs
import android.provider.Settings
import android.text.format.Formatter
import android.widget.*
import java.io.File

class MainActivity : Activity() {
    private lateinit var out: TextView
    private var junk: List<File> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(40, 40, 40, 40) }
        root.addView(TextView(this).apply { text = "CleanGuard"; textSize = 26f })
        fun btn(t: String, a: () -> Unit) = root.addView(Button(this).apply { text = t; setOnClickListener { a() } })
        btn("Status do aparelho") { status() }
        btn("Verificar segurança (apps)") { scan() }
        btn("Procurar arquivos inúteis") { findJunk() }
        btn("Limpar arquivos encontrados") { clean() }
        out = TextView(this).apply { textSize = 14f; setPadding(0, 24, 0, 0) }
        root.addView(out)
        setContentView(ScrollView(this).apply { addView(root) })
        status()
    }

    private fun ui(s: String) = runOnUiThread { out.text = s }

    private fun status() {
        val am = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val mi = ActivityManager.MemoryInfo().also { am.getMemoryInfo(it) }
        val st = StatFs(Environment.getDataDirectory().path)
        ui("RAM livre: ${Formatter.formatFileSize(this, mi.availMem)} de ${Formatter.formatFileSize(this, mi.totalMem)}\n" +
           "Armazenamento livre: ${Formatter.formatFileSize(this, st.availableBytes)} de ${Formatter.formatFileSize(this, st.totalBytes)}\n" +
           "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
    }

    private fun scan() {
        ui("Verificando apps...")
        Thread {
            val r = Scanner.scanApps(this)
            ui(if (r.isEmpty()) "Nenhum app suspeito encontrado."
               else "${r.size} app(s) suspeito(s):\n\n" + r.joinToString("\n\n") {
                   "${it.label} (${it.pkg})\nRisco: ${it.risk}\n- " + it.reasons.joinToString("\n- ")
               })
        }.start()
    }

    private fun hasStorageAccess(): Boolean {
        if (Build.VERSION.SDK_INT >= 30) {
            if (Environment.isExternalStorageManager()) return true
            startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:$packageName")))
        } else {
            requestPermissions(arrayOf(android.Manifest.permission.WRITE_EXTERNAL_STORAGE), 1)
        }
        ui("Conceda o acesso a arquivos e toque novamente no botão.")
        return false
    }

    private fun findJunk() {
        if (!hasStorageAccess()) return
        ui("Procurando...")
        Thread {
            junk = Cleaner.findJunk()
            ui("${junk.size} arquivo(s) inúteis, ${Formatter.formatFileSize(this, junk.sumOf { it.length() })}.\n" +
               "Toque em \"Limpar\" para apagar.\n\n" + junk.take(30).joinToString("\n") { it.path })
        }.start()
    }

    private fun clean() {
        Thread {
            val freed = Cleaner.delete(junk) + Cleaner.clearOwnCache(this)
            junk = emptyList()
            ui("Limpeza concluída. Liberado: ${Formatter.formatFileSize(this, freed)}")
        }.start()
    }
}
