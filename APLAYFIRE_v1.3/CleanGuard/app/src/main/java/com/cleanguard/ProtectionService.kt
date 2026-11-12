package com.cleanguard

import android.app.NotificationManager
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Environment
import android.os.FileObserver
import android.os.IBinder
import android.widget.Toast
import java.io.File
import java.util.concurrent.Executors

class ProtectionService : Service() {
    private val obs = mutableListOf<FileObserver>()
    private val pool = Executors.newSingleThreadExecutor()
    private var rcv: BroadcastReceiver? = null

    companion object {
        fun start(c: Context) {
            val i = Intent(c, ProtectionService::class.java)
            if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(i) else c.startService(i)
        }
    }

    override fun onBind(i: Intent?): IBinder? = null

    override fun onStartCommand(i: Intent?, flags: Int, startId: Int): Int {
        Notifier.channels(this)
        val n = Notifier.ongoing(this)
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE) else startForeground(1, n)
        if (obs.isEmpty()) watch()
        return START_STICKY
    }

    private fun watch() {
        val root = Environment.getExternalStorageDirectory()
        for (name in listOf("Download", "Documents", "Telegram", "Bluetooth")) {
            val d = File(root, name)
            if (!d.isDirectory || !ThreatLog.setting(this, "f_$name", true)) continue
            @Suppress("DEPRECATION")
            val o = object : FileObserver(d.path, FileObserver.CLOSE_WRITE or FileObserver.MOVED_TO) {
                override fun onEvent(event: Int, path: String?) {
                    if (path == null) return
                    val n = path.lowercase()
                    if (n.endsWith(".crdownload") || n.endsWith(".part") || n.endsWith(".tmp") || n.endsWith(".download")) return
                    pool.execute { Guard.checkFile(this@ProtectionService, File(d, path)) }
                }
            }
            o.startWatching(); obs += o
        }
        val r = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                val pkg = i.data?.schemeSpecificPart ?: return
                if (i.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
                pool.execute { Guard.checkPackage(c, pkg) }
            }
        }
        val f = IntentFilter(Intent.ACTION_PACKAGE_ADDED).apply { addDataScheme("package") }
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(r, f, Context.RECEIVER_EXPORTED) else registerReceiver(r, f)
        rcv = r
        if (ThreatLog.setting(this, "sigs", true)) pool.execute { SignatureUpdater.update(this) }
    }

    override fun onDestroy() {
        obs.forEach { it.stopWatching() }; obs.clear()
        rcv?.let { unregisterReceiver(it) }
        pool.shutdown()
        super.onDestroy()
    }
}

class ActionReceiver : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) {
        val p = i.getStringExtra("path") ?: return
        if (Guard.safeDelete(p)) Toast.makeText(c, "Arquivo apagado", Toast.LENGTH_SHORT).show()
        c.getSystemService(NotificationManager::class.java).cancel(i.getIntExtra("id", 0))
    }
}

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) { if (ThreatLog.enabled(c) && ThreatLog.setting(c, "boot", true)) ProtectionService.start(c) }
}
