package com.cleanguard

import android.content.Context
import android.os.Environment
import java.io.File

object Cleaner {
    private val JUNK_EXT = setOf("tmp", "temp", "log", "bak", "thumbdata", "cache", "old")

    fun findJunk(): List<File> {
        val root = Environment.getExternalStorageDirectory()
        val found = mutableListOf<File>()
        fun walk(d: File, depth: Int) {
            if (depth > 8) return
            val children = d.listFiles() ?: return
            for (f in children) {
                if (f.isDirectory) {
                    if (f.name == "Android" && d == root) continue // dados de outros apps
                    walk(f, depth + 1)
                } else if (f.extension.lowercase() in JUNK_EXT || f.length() == 0L) found += f
            }
        }
        walk(root, 0)
        return found
    }

    fun delete(files: List<File>): Long {
        var freed = 0L
        for (f in files) { val s = f.length(); if (f.delete()) freed += s }
        return freed
    }

    fun clearOwnCache(ctx: Context): Long {
        var n = 0L
        for (d in listOfNotNull(ctx.cacheDir, ctx.externalCacheDir)) {
            d.walkBottomUp().forEach { if (it != d) { n += it.length(); it.delete() } }
        }
        return n
    }
}
