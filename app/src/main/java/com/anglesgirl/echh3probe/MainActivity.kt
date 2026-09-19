package com.anglesgirl.echh3probe

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.telephony.TelephonyManager
import android.view.ViewGroup
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.InetAddress
import java.net.URL
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import kotlin.concurrent.thread

/**
 * ECH over H3 真机探针：
 *  1) 用自有网关 DoH 取目标域名的 A 记录与 HTTPS 记录里的 ech=
 *  2) 把 ECHConfigList 交给 Rust（quiche + 打过补丁的 BoringSSL）
 *  3) 走 QUIC/H3 拉一张真实图片，报出握手 / 首字节 / 总耗时 / 状态码
 *
 * 结果同时落盘（filesDir/last-run.txt）并上报到 log.anglesgirl.eu.org，
 * 崩溃也会被捕获上报 —— 不需要用户截图，结果不会因为崩溃而丢失。
 */
class MainActivity : Activity() {

    private lateinit var out: TextView
    private lateinit var hostInput: EditText
    private lateinit var btn: Button
    private lateinit var btnWv: Button
    private lateinit var btnColo: Button
    private lateinit var btnAlt: Button
    private lateinit var root: LinearLayout
    private val log = StringBuilder()
    private var wv: WebView? = null

    private val imgPath =
        "/c/1200x1200_80_webp/img-master/img/2026/09/17/22/57/33/149781675_p0_master1200.jpg"
    private val logFile by lazy { File(filesDir, "last-run.txt") }
    private val crashFile by lazy { File(filesDir, "last-crash.txt") }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Android 15+ 对 targetSdk 35+ 的应用强制 edge-to-edge：内容会画到状态栏下面，
        // 顶部第一行控件被状态栏盖住（用户实测"按钮被挡住"）。显式恢复传统行为。
        if (android.os.Build.VERSION.SDK_INT >= 30) {
            window.setDecorFitsSystemWindows(true)
        }
        installCrashHandler()
        // 标题栏带版本号：用户一眼能确认装的是哪一版（避免"装的不是我发的那份"这种排查黑洞）
        title = "ECH-H3 探针 v" + BuildConfig.VERSION_NAME

        root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            fitsSystemWindows = true
        }
        // 按钮固定吸顶：按钮行横排 + 日志块按权重占满剩余空间，
        // 避免日志太长时把按钮挤出可视区域（用户实测"看不到按钮"）。
        val bar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        btn = Button(this).apply {
            text = "原生测试"
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        btnWv = Button(this).apply {
            text = "WebView 直开"
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        btnAlt = Button(this).apply {
            text = "Alt-Svc 猜想"
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        bar.addView(btn)
        bar.addView(btnWv)
        bar.addView(btnAlt)
        // 按钮行必须显式 MATCH_PARENT：否则父行按 wrap_content 测量，
        // 里面 width=0 + weight=1 的按钮会被算成 0 宽（实测按钮完全不可见）。
        root.addView(bar, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        // 目标域名可编辑：H3 是否可用因域而异，探针必须能测任意站点。
        hostInput = EditText(this).apply {
            hint = "目标域名，如 api.bgm.tv"
            setText("i.pximg.net")
        }
        root.addView(
            hostInput,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
        )
        val presets = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        listOf("i.pximg.net", "api.bgm.tv", "lain.bgm.tv", "javchu.com", "hanime1.me", "ao3").forEach { label ->
            val presetHost = if (label == "ao3") "archiveofourown.org" else label
            presets.addView(Button(this).apply {
                text = label
                textSize = 9f
                setPadding(0, 0, 0, 0)
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                setOnClickListener { hostInput.setText(presetHost) }
            })
        }
        // 预设行同样必须 MATCH_PARENT：父行 wrap_content 时 width=0+weight=1 的子按钮会被算成 0 宽
        root.addView(
            presets,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
        )
        out = TextView(this).apply { textSize = 12f; setPadding(24, 24, 24, 24) }
        root.addView(
            ScrollView(this).apply { addView(out) },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f),
        )
        setContentView(root)

        // 上次结果先显示出来（崩溃也不会丢）
        if (logFile.exists()) {
            synchronized(log) {
                log.setLength(0)
                log.append(logFile.readText())
            }
            out.text = log.toString()
        } else {
            // 首次打开自动跑一遍
            btn.post { runTests() }
        }

        btn.setOnClickListener { runTests() }
        btnWv.setOnClickListener { runWebViewArm() }
        btnColo = Button(this).apply {
            text = "colo 对照"
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        bar.addView(btnColo)
        btnColo.setOnClickListener {
            thread {
                runColoTraceArm()
                finishRun("colo-trace")
            }
        }
        btnAlt.setOnClickListener {
            thread {
                runAltSvcArm(true, "注入 Alt-Svc: h3")
                runAltSvcArm(false, "对照：不注入")
                finishRun("alt-svc-arm")
            }
        }
    }

    // ---------------- 基础设施 ----------------

    /** 线程安全地追加一行：后台线程也敢调（UI 更新切回主线程） */
    private fun say(s: String) {
        synchronized(log) { log.append(s).append('\n') }
        runOnUiThread { out.text = synchronized(log) { log.toString() } }
    }

    private fun currentLog(): String = synchronized(log) { log.toString() }

    private fun persistLog(extra: String = "") {
        try {
            logFile.writeText(currentLog() + extra)
        } catch (_: Throwable) {
        }
    }

    /** 只有主线程能碰视图：所有 UI 变更都从这里走 */
    private fun ui(block: () -> Unit) {
        runOnUiThread(block)
    }

    /** MCC/MNC → 运营商（权威标识；运营商名字常被设备/系统映射错，实测广电被标成电信） */
    private fun opLabel(o: String): String = when (o) {
        "46000", "46002", "46004", "46007", "46008" -> "移动"
        "46015" -> "广电(走移动网)"
        "46001", "46006", "46009" -> "联通"
        "46003", "46005", "46011" -> "电信"
        "" -> "未知"
        else -> "其他($o)"
    }

    private fun carrier(): String = try {
        val tm = getSystemService(TELEPHONY_SERVICE) as TelephonyManager
        val net = tm.networkOperator.orEmpty()   // 当前驻留网络的 MCC+MNC
        val sim = tm.simOperator.orEmpty()       // 卡的 MCC+MNC
        val roaming = try {
            tm.isNetworkRoaming
        } catch (_: Throwable) {
            false
        }
        "网络=${tm.networkOperatorName}[$net→${opLabel(net)}] 卡=${tm.simOperatorName}[$sim→${opLabel(sim)}] 漫游=$roaming"
    } catch (e: Exception) {
        "网络=读取失败(${e.message})"
    }

    private fun nowIso(): String {
        val f = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
        f.timeZone = TimeZone.getTimeZone("UTC")
        return f.format(Date())
    }

    /** 上报到自有诊断端点（失败绝不影响主流程） */
    private fun upload(event: String, fields: Map<String, String>) {
        val payload = fields.toMutableMap()
        payload["carrier"] = carrier()
        payload["app_sha"] = BuildConfig.VERSION_NAME
        thread {
            try {
                val o = JSONObject()
                o.put("app", "ech-h3-probe")
                o.put("event", event)
                o.put("timestamp", nowIso())
                for ((k, v) in payload) o.put(k, v.take(4000))
                val conn = (URL(ENDPOINT).openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    doOutput = true
                    setRequestProperty("Content-Type", "application/json")
                    connectTimeout = 10_000
                    readTimeout = 10_000
                }
                conn.outputStream.use { it.write(o.toString().toByteArray()) }
                conn.responseCode
                conn.disconnect()
            } catch (_: Throwable) {
                // 上报失败就算了，绝不影响测试结果
            }
        }
    }

    /** 崩溃捕获：写盘 + 上报 + 交给原 handler（保持系统默认行为） */
    private fun installCrashHandler() {
        val prev = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            try {
                val sw = StringWriter()
                e.printStackTrace(PrintWriter(sw))
                val trace = sw.toString()
                crashFile.writeText(trace)
                persistLog("\n\n== 崩溃 ==\n" + trace)
                upload(
                    "crash",
                    mapOf(
                        "stack" to trace,
                        "log" to currentLog(),
                        "thread" to (t?.name ?: "?"),
                    ),
                )
                Thread.sleep(1500) // 给上报一点时间
            } catch (_: Throwable) {
            }
            prev?.uncaughtException(t, e)
        }
    }

    // ---------------- 第一组：原生通道（带 ECH / 无 ECH） ----------------

    private fun runTests() {
        btn.isEnabled = false
        synchronized(log) { log.setLength(0) }
        thread {
            try {
                say("== ECH + HTTP/3 探针 ==")
                say("时间 : " + SimpleDateFormat("MM-dd HH:mm:ss", Locale.CHINA).format(Date()))
                say("载体 : " + carrier())
                say("网关 : " + BuildConfig.DOH_URL)
                say("版本 : " + BuildConfig.VERSION_NAME)
                say("")

                var caPath = ""
                try {
                    caPath = exportSystemCas()
                    say("[CA] 系统证书已导出：" + File(caPath).length() + " 字节")
                } catch (e: Exception) {
                    say("[CA] 导出失败：" + e.message + "（将退化为系统默认 CA）")
                }

                val host = hostInput.text.toString().trim().ifBlank { "i.pximg.net" }
                say("[目标] $host")

                // 两种解析来源必须分开看：自有网关（择优 IP）vs 系统原生 DNS。
                // H3 是否可用与"连到哪个 IP"强相关（例：i.pximg.net 原生不支持 H3，经自有网关才支持）。
                val gateway = try {
                    resolveViaGateway(host)
                } catch (e: Exception) {
                    say("[DoH] 网关解析失败：" + e.message)
                    null
                }
                val echB64 = gateway?.second.orEmpty()
                val sources = LinkedHashMap<String, String>()
                gateway?.first?.let { sources["网关（自有 DoH）"] = it }
                runCatching {
                    InetAddress.getAllByName(host)
                        .filterIsInstance<Inet4Address>()
                        .map { it.hostAddress }
                        .take(2)
                }.getOrNull()?.forEach { sources["系统原生 DNS"] = it }
                if (sources.isEmpty()) {
                    say("== 结束（解析失败）==")
                    finishRun("probe-run")
                    return@thread
                }
                sources.forEach { (label, ip) -> say("[解析] $label → $ip") }
                say("[ECH ] " + (if (echB64.isEmpty()) "缺失 ✗" else echB64.length.toString() + " 字符 ✓"))
                say("")

                val realPath = if (host.endsWith("pximg.net")) imgPath else "/"
                val referer = if (host.endsWith("pximg.net")) "https://www.pixiv.net/" else "https://$host/"

              for ((srcLabel, ip) in sources) {
                say("########## 来源：$srcLabel（$ip）##########")
                // 关键对照：带 ECH 与 不带 ECH（明文 SNI）
                val arms = listOf("带 ECH" to echB64, "无 ECH（明文 SNI）" to "")
                for ((armName, armEch) in arms) {
                    say("===== [$srcLabel] $armName =====")
                    for (i in 1..3) {
                        say("---- $armName 第 $i 次 ----")
                        val t0 = System.currentTimeMillis()
                        val json = try {
                            ProbeNative.h3Fetch(host, ip, armEch, realPath, referer, caPath, "")
                        } catch (t: Throwable) {
                            say("JNI 异常：" + t.message)
                            continue
                        }
                        val wall = System.currentTimeMillis() - t0
                        val o = JSONObject(json)
                        val err = o.optString("error", "")
                        if (err.isNotEmpty() && err != "null") say("错误   : " + err)
                        say("握手   : " + o.optLong("hs_ms") + " ms ｜ ALPN=" + o.optString("alpn"))
                        say("ECH    : override=" + o.optString("ech_override", "null") +
                                " ｜ retry=" + o.optInt("ech_retry_len") + " 字节")
                        say("H3     : status=" + o.optInt("status") + " ｜ 首字节=" + o.optLong("first_byte_ms") +
                                "ms ｜ 总耗时=" + o.optLong("total_ms") + "ms ｜ 字节=" + o.optLong("body_len"))
                        say("响应头 : cf-ray=" + o.optString("cf_ray") + " server=" + o.optString("server"))
                        say("诊断   : sent=" + o.optLong("sent") + " recv=" + o.optLong("recv") +
                                " peer_err=" + o.optString("peer_err", "-") + " ｜ 墙钟=" + wall + "ms")
                        say("")
                    }
                }
              }
                say("== 结束 ==")
                finishRun("probe-run")
            } catch (t: Throwable) {
                say("测试异常：" + t)
                finishRun("probe-run-error")
            }
        }
    }

    private fun finishRun(event: String) {
        persistLog()
        upload(event, mapOf("log" to currentLog(), "gateway" to BuildConfig.DOH_URL))
        ui { btn.isEnabled = true; btnWv.isEnabled = true }
    }

    // ---------------- 第二组：WebView 直开 ----------------

    /**
     * 直接 loadUrl，不拦截、不注入、不给 ECH。
     * 目的：验证"第一次连接是否被 TCP RST"（若被 RST，H3 永远没机会上场）。
     * 目标选 www.pixiv.net：CF 托管（系统 DNS 给 CF IP，可达），但 SNI 在国内被拦
     * —— 失败原因就只可能是 SNI/协议，而不是 IP 不可达。
     */
    private fun runWebViewArm() {
        btnWv.isEnabled = false
        synchronized(log) { log.setLength(0) }
        try {
            say("===== WebView 直开（不拦截/不注入/无 ECH）=====")
            say("载体 : " + carrier())
            val target = "https://www.pixiv.net/"
            say("目标 : " + target)
            var reported = false

            val view = wv ?: WebView(this).also { w ->
                w.settings.javaScriptEnabled = true
                w.settings.domStorageEnabled = true
                w.layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    (resources.displayMetrics.density * 260).toInt(),
                )
                w.webViewClient = object : WebViewClient() {
                    override fun onPageFinished(v: WebView?, url: String?) {
                        if (reported) return
                        reported = true
                        say("结果 : 页面加载完成 ✓ url=" + url)
                        say("说明 : 若成功且连接为 QUIC/H3，则\"明文也能通\"的判断成立。")
                        afterWv()
                    }

                    override fun onReceivedError(
                        v: WebView?,
                        request: WebResourceRequest?,
                        error: WebResourceError?,
                    ) {
                        if (request?.isForMainFrame != true) return
                        reported = true
                        say("结果 : 加载失败 ✗ code=" + error?.errorCode + " desc=" + error?.description)
                        say("说明 : 负数错误码（如 -101/-102）多为连接被重置/拒绝 → 首连 TCP 就被掐，H3 无机可乘。")
                        afterWv()
                    }
                }
                root.addView(w, 2)
                wv = w
                w
            }

            view.loadUrl(target)
            Handler(Looper.getMainLooper()).postDelayed({
                if (!reported) {
                    reported = true
                    say("结果 : 20 秒内既没完成也没报错（大概率卡在被丢弃的连接上）")
                    afterWv()
                }
            }, 20_000)
        } catch (t: Throwable) {
            say("WebView 测试异常：" + t)
            afterWv()
        }
    }

    private fun afterWv() {
        persistLog()
        upload("webview-arm", mapOf("log" to currentLog()))
        ui { btn.isEnabled = true; btnWv.isEnabled = true }
    }

    // ---------------- DoH / CA ----------------

    /**
     * Alt-Svc 猜想：拦截主文档时，在合成响应里塞 `Alt-Svc: h3`，
     * 看 WebView 会不会把同一个站的后续请求（我们不拦截、让 WebView 自己连）
     * 升级到 HTTP/3。协议由页面侧 nextHopProtocol 回报 —— 这是唯一能拿到真实协议的办法。
     */
    private fun runAltSvcArm(withAltSvc: Boolean, label: String) {
        say("---- $label ----")
        val latch = java.util.concurrent.CountDownLatch(1)
        val density = resources.displayMetrics.density
        ui {
            val w = WebView(this)
            w.settings.javaScriptEnabled = true
            w.layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, (density * 180).toInt(),
            )
            w.addJavascriptInterface(
                object {
                    @android.webkit.JavascriptInterface
                    fun report(s: String) {
                        say("  页面回报 : " + s)
                        latch.countDown()
                    }
                },
                "AltSvcProbe",
            )
            w.webViewClient = object : WebViewClient() {
                override fun shouldInterceptRequest(
                    v: WebView?,
                    request: WebResourceRequest?,
                ): WebResourceResponse? {
                    val u = request?.url?.toString() ?: return null
                    if (!u.contains("intercept=1")) return null // 其它请求放行 → 由 WebView 自己建连
                    val html =
                        "<html><body><script>" +
                            "var done=function(m){AltSvcProbe.report(m);};" +
                            "fetch('https://www.pixiv.net/robots.txt',{cache:'no-store'})" +
                            ".then(function(r){return r.arrayBuffer().then(function(b){" +
                            "var es=performance.getEntriesByType('resource').filter(function(e){return e.nextHopProtocol;});" +
                            "var p=es.length?es[es.length-1].nextHopProtocol:'no-entry';" +
                            "done('子资源成功 status='+r.status+' 协议='+p+' 字节='+b.byteLength);});})" +
                            ".catch(function(e){done('子资源失败 '+e);});" +
                            "setTimeout(function(){done('超时：12 秒无结果');},12000);" +
                            "</script></body></html>"
                    val resp = WebResourceResponse(
                        "text/html", "utf-8",
                        java.io.ByteArrayInputStream(html.toByteArray()),
                    )
                    if (withAltSvc) {
                        resp.responseHeaders = mapOf("Alt-Svc" to "h3=\":443\"; ma=86400")
                    }
                    return resp
                }
            }
            root.addView(w) // 追加在最后（不能给越界索引，否则 IndexOutOfBounds）
            w.loadUrl("https://www.pixiv.net/?intercept=1")
        }
        if (!latch.await(20, java.util.concurrent.TimeUnit.SECONDS)) {
            say("  （20 秒无回报）")
        }
        say("")
    }

    /** colo 对照：同一 zone 的 /cdn-cgi/trace，H3(quiche) 与 TCP 各取 2 次，比 colo 与延时 */
    private fun runColoTraceArm() {
        say("===== colo 对照（/cdn-cgi/trace，同一 zone）=====")
        say("载体 : " + carrier())
        val gwHost = BuildConfig.DOH_URL.substringAfter("https://").substringBefore("/")
        say("目标 : $gwHost/cdn-cgi/trace")
        val gwIp = try {
            resolveViaGateway(gwHost).first
        } catch (e: Exception) {
            say("解析失败: " + e.message)
            return
        }
        val caPath = try {
            exportSystemCas()
        } catch (_: Exception) {
            ""
        }

        say("---- H3（quiche）----")
        for (i in 1..2) {
            val f = File(cacheDir, "trace-h3-$i.txt")
            val t0 = System.currentTimeMillis()
            val json = runCatching {
                ProbeNative.h3Fetch(gwHost, gwIp, "", "/cdn-cgi/trace", "", caPath, f.absolutePath)
            }.getOrNull()
            val wall = System.currentTimeMillis() - t0
            val o = json?.let { runCatching { JSONObject(it) }.getOrNull() }
            val body = if (f.exists()) f.readText() else ""
            say("  第 $i 次 status=" + (o?.optInt("status") ?: -1) + " 握手=" + (o?.optLong("hs_ms") ?: -1) +
                    "ms 总=" + (o?.optLong("total_ms") ?: -1) + "ms 墙钟=" + wall + "ms")
            say("    " + traceSummary(body))
            f.delete()
        }

        say("---- TCP（HttpURLConnection）----")
        for (i in 1..2) {
            val t0 = System.currentTimeMillis()
            val body = runCatching {
                val c = (URL("https://$gwHost/cdn-cgi/trace").openConnection() as HttpURLConnection).apply {
                    connectTimeout = 8000
                    readTimeout = 12000
                }
                val text = c.inputStream.bufferedReader().use { it.readText() }
                c.disconnect()
                text
            }.getOrElse { "ERR " + it.message }
            say("  第 $i 次 墙钟=" + (System.currentTimeMillis() - t0) + "ms")
            say("    " + traceSummary(body))
        }
        say("")
    }

    /** 从 trace 里挑关键信息：落到哪个边缘、走的什么协议、SNI 是否加密 */
    private fun traceSummary(body: String): String {
        if (body.startsWith("ERR")) return body
        val want = listOf("ip=", "colo=", "loc=", "http=", "sni=", "tls=", "kex=")
        val picked = body.lines().filter { line -> want.any { line.startsWith(it) } }
        return if (picked.isEmpty()) "(无 trace 内容)" else picked.joinToString("  ")
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

    private companion object {
        const val ENDPOINT = "https://log.anglesgirl.eu.org/v1/events"
    }
}
