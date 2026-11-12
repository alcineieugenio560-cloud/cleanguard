package com.cleanguard

import android.annotation.SuppressLint
import android.app.Activity
import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.StatFs
import android.provider.Settings
import android.webkit.JavascriptInterface
import android.webkit.WebView
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

class MainActivity : Activity() {
    private lateinit var web: WebView
    private var junk: List<File> = emptyList()

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = Color.parseColor("#D61F26")
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != PackageManager.PERMISSION_GRANTED)
            requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 2)
        web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.addJavascriptInterface(Bridge(), "Android")
        web.loadUrl("file:///android_asset/index.html")
        setContentView(web)
        if (ThreatLog.enabled(this) && storageOk()) ProtectionService.start(this)
    }

    override fun onResume() {
        super.onResume()
        if (::web.isInitialized) emit("prot", Bridge().protection())
    }

    private fun emit(type: String, json: Any) =
        runOnUiThread { web.evaluateJavascript("onNative('$type',$json)", null) }

    private fun storageOk(): Boolean = if (Build.VERSION.SDK_INT >= 30) Environment.isExternalStorageManager()
        else checkSelfPermission(android.Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED

    private fun hasAccess(): Boolean {
        if (storageOk()) return true
        if (Build.VERSION.SDK_INT >= 30)
            startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:$packageName")))
        else requestPermissions(arrayOf(android.Manifest.permission.WRITE_EXTERNAL_STORAGE), 1)
        return false
    }

    inner class Bridge {
        @JavascriptInterface
        fun status(): String {
            val am = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            val mi = ActivityManager.MemoryInfo().also { am.getMemoryInfo(it) }
            val st = StatFs(Environment.getDataDirectory().path)
            return JSONObject().put("rt", mi.totalMem).put("rf", mi.availMem)
                .put("st", st.totalBytes).put("sf", st.availableBytes).put("v", Build.VERSION.RELEASE).toString()
        }

        @JavascriptInterface
        fun scan() {
            Thread {
                val arr = JSONArray()
                Scanner.scanApps(this@MainActivity).forEach {
                    arr.put(JSONObject().put("n", it.label).put("p", it.pkg).put("r", it.risk).put("w", JSONArray(it.reasons)))
                }
                emit("scan", arr)
            }.start()
        }

        @JavascriptInterface
        fun findJunk() {
            runOnUiThread {
                if (!hasAccess()) { emit("perm", "{}"); return@runOnUiThread }
                Thread {
                    junk = Cleaner.findJunk()
                    emit("junk", JSONObject().put("c", junk.size).put("b", junk.sumOf { it.length() })
                        .put("f", JSONArray(junk.take(5).map { it.path })))
                }.start()
            }
        }

        @JavascriptInterface
        fun clean() {
            Thread {
                val freed = Cleaner.delete(junk) + Cleaner.clearOwnCache(this@MainActivity)
                junk = emptyList()
                emit("clean", JSONObject().put("b", freed))
            }.start()
        }

        @JavascriptInterface
        fun protection(): String = ThreatLog.json(this@MainActivity)
            .put("sigs", Scanner.blocklist(this@MainActivity).size).toString()

        @JavascriptInterface
        fun setProtection(on: Boolean) {
            runOnUiThread {
                if (!on) {
                    stopService(Intent(this@MainActivity, ProtectionService::class.java))
                    ThreatLog.setEnabled(this@MainActivity, false)
                } else if (!hasAccess()) {
                    emit("perm", "{}")
                } else {
                    ThreatLog.setEnabled(this@MainActivity, true)
                    ProtectionService.start(this@MainActivity)
                }
                emit("prot", protection())
            }
        }

        @JavascriptInterface
        fun updateSigs() {
            Thread { emit("sigs", JSONObject().put("n", SignatureUpdater.update(this@MainActivity))) }.start()
        }

        @JavascriptInterface
        fun del(path: String) { Guard.safeDelete(path); emit("prot", protection()) }

        @JavascriptInterface
        fun uninstall(pkg: String) {
            startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:$pkg")))
        }
    }
}
