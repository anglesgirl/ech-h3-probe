package com.anglesgirl.echh3probe

import android.app.Activity
import android.os.Bundle
import android.telephony.TelephonyManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

/**
 * ECH over H3 真机探针：
 *  1) 用自有网关 DoH 取目标域名的 A 记录（ipv4hint / A）与 HTTPS 记录里的 ech=
 *  2) 把 ECHConfigList 交给 Rust（quiche + 打过补丁的 BoringSSL）
 *  3) 走 QUIC/H3 拉一张真实图片，报出握手 / 首字节 / 总耗时 / 状态码
 */
class MainActivity : Activity() {

    private lateinit var out: TextView
    private lateinit var btn: Button
    private val log = StringBuilder()

    private val imgPath =
        "/c/1200x1200_80_webp/img-master/img/2026/09/17/22/57/33/149781675_p0_master1200.jpg"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        btn = Button(this).apply { text = "开始测试" }
        out = TextView(this).apply {
            textSize = 12f
            setPadding(24, 24, 24, 24)
        }
        root.addView(btn)
        root.addView(ScrollView(this).apply { addView(out) })
        setContentView(root)
        btn.setOnClickListener { runTests() }
        runTests()
    }

    private fun say(s: String) {
        runOnUiThread {
            log.append(s).append('\n')
            out.text = log.toString()
        }
    }

    private fun carrier(): String = try {
        val tm = getSystemService(TELEPHONY_SERVICE) as TelephonyManager
        val op = tm.networkOperatorName
        val sim = tm.simOperatorName
        "网络=$op  卡=$sim"
    } catch (e: Exception) {
        "网络=未知"
    }

    private fun runTests() {
        btn.isEnabled = false
        log.setLength(0)
        thread {
            say("== ECH + HTTP/3 探针 ==")
            say("时间 : " + SimpleDateFormat("MM-dd HH:mm:ss", Locale.CHINA).format(Date()))
            say("载体 : " + carrier())
            say("网关 : " + BuildConfig.DOH_URL)
            say("")

            val caPath: String
            try {
                caPath = exportSystemCas()
                say("[CA] 系统证书已导出：" + File(caPath).length() + " 字节")
            } catch (e: Exception) {
                say("[CA] 导出失败：" + e.message)
                caPath = ""
            }

            val host = "i.pximg.net"
            val (ip, echB64) = try {
                resolveViaGateway(host)
            } catch (e: Exception) {
                say("[DoH] 解析失败：" + e.message)
                btn.isEnabled = true
                return@thread
            }
            say("[DoH] $host → $ip，ECH " + (if (echB64.isEmpty()) "缺失 ✗" else echB64.length.toString() + " 字符 ✓"))
            say("")

            // 关键对照：带 ECH 与 不带 ECH（用户判断：H3 暴露域名也能通，需要数据)
            val arms = listOf("带 ECH" to echB64, "无 ECH（明文 SNI）" to "")
            for ((armName, armEch) in arms) {
            say("===== $armName =====")
            for (i in 1..3) {
                say("---- $armName 第 $i 次 ----")
                val t0 = System.currentTimeMillis()
                val json = try {
                    ProbeNative.h3Fetch(host, ip, armEch, imgPath, "https://www.pixiv.net/", caPath)
                } catch (t: Throwable) {
                    say("JNI 异常：" + t.message)
                    continue
                }
                val wall = System.currentTimeMillis() - t0
                val o = JSONObject(json)
                val err = o.optString("error", "")
                if (err.isNotEmpty() && err != "null") say("错误   : " + err)
                say("握手   : " + o.optLong("hs_ms") + " ms ｜ ALPN=" + o.optString("alpn"))
                say("ECH    : override=" + (o.optString("ech_override", "null")) +
                        " ｜ retry=" + o.optInt("ech_retry_len") + " 字节")
                say("H3     : status=" + o.optInt("status") + " ｜ 首字节=" + o.optLong("first_byte_ms") +
                        "ms ｜ 总耗时=" + o.optLong("total_ms") + "ms ｜ 字节=" + o.optLong("body_len"))
                say("响应头 : cf-ray=" + o.optString("cf_ray") + " server=" + o.optString("server"))
                say("诊断   : sent=" + o.optLong("sent") + " recv=" + o.optLong("recv") +
                        " peer_err=" + o.optString("peer_err", "-") + " ｜ 墙钟=" + wall + "ms")
                say("")
            }
            }
            say("== 结束 ==")
            btn.isEnabled = true
        }
    }

    /** DoH：拿 A 记录的 IP 和 HTTPS 记录里的 ech= */
    private fun resolveViaGateway(host: String): Pair<String, String> {
        var ip = ""
        var echB64 = ""
        for (type in listOf("A", "HTTPS")) {
            val url = URL(BuildConfig.DOH_URL + "?name=" + host + "&type=" + type)
            val conn = (url.openConnection() as HttpURLConnection).apply {
                setRequestProperty("accept", "application/dns-json")
                connectTimeout = 8000
                readTimeout = 8000
            }
            val body = BufferedInputStream(conn.inputStream).bufferedReader().readText()
            conn.disconnect()
            val json = JSONObject(body)
            val answers = json.optJSONArray("Answer") ?: continue
            for (i in 0 until answers.length()) {
                val data = answers.getJSONObject(i).optString("data", "")
                if (type == "A" && ip.isEmpty() && data.matches(Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+$"))) {
                    ip = data
                }
                if (type == "HTTPS") {
                    for (tok in data.split(" ")) {
                        if (tok.startsWith("ech=") && echB64.isEmpty()) echB64 = tok.substring(4)
                    }
                }
            }
        }
        if (ip.isEmpty()) throw IllegalStateException("网关没给出 A 记录")
        return Pair(ip, echB64)
    }

    /** 把系统 CA 导出成一个 PEM（Rust 侧用 load_verify_locations_from_file 读它） */
    private fun exportSystemCas(): String {
        val f = File(cacheDir, "system-ca.pem")
        val ks = KeyStore.getInstance("AndroidCAStore").apply { load(null, null) }
        val sb = StringBuilder()
        val aliases = ks.aliases()
        while (aliases.hasMoreElements()) {
            val a = aliases.nextElement()
            val cert = ks.getCertificate(a) as? X509Certificate ?: continue
            sb.append("-----BEGIN CERTIFICATE-----\n")
            sb.append(android.util.Base64.encodeToString(cert.encoded, android.util.Base64.NO_WRAP))
            sb.append("\n-----END CERTIFICATE-----\n")
        }
        f.writeText(sb.toString())
        return f.absolutePath
    }
}
