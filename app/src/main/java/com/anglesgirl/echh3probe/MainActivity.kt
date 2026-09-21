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
    private lateinit var ipInput: EditText
    private lateinit var echInput: EditText
    private lateinit var btn: Button
    private lateinit var btnWv: Button
    private lateinit var btnColo: Button
    private lateinit var btnAlt: Button
    private lateinit var root: LinearLayout
    private val log = StringBuilder()
    private var wv: WebView? = null
    private lateinit var btnNet: Button
    private lateinit var btnTcp: Button
    private lateinit var verdict: TextView
    private lateinit var advancedBox: LinearLayout
    private lateinit var btnAdv: Button
    private lateinit var dohInput: EditText

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
        // ---- 主入口：一键体检（本机当前网络是否支持 ECH / H3）----
        btnNet = Button(this).apply {
            text = "检测本机网络（ECH / H3）"
            textSize = 16f
        }
        root.addView(
            btnNet,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
        )
        verdict = TextView(this).apply {
            textSize = 14f
            setPadding(28, 20, 28, 20)
        }
        root.addView(
            verdict,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
        )
        // 高级区：默认收起（主界面只留「一键体检」+ 结论），点「高级对照」才展开。
        // 目标域名可编辑：H3 是否可用因域而异，探针必须能测任意站点。
        advancedBox = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = ViewGroup.GONE
        }
        btnAdv = Button(this).apply {
            text = "高级：对照测试（指定域名 / IP / ECH 注入）"
            textSize = 11f
        }
        root.addView(
            btnAdv,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
        )
        root.addView(
            advancedBox,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
        )
        // DoH 地址：公开仓库不内置网关地址，这里给用户自己填；填过就存下来，重启仍生效。
        dohInput = EditText(this).apply {
            hint = "DoH 地址（查 IP 与 ech=，例 https://你的域名/dns-query）"
            textSize = 10f
            setText(currentDoh())
        }
        dohInput.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                prefs().edit().putString("doh", s?.toString()?.trim().orEmpty()).apply()
            }
        })
        advancedBox.addView(
            dohInput,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
        )
        hostInput = EditText(this).apply {
            hint = "目标域名，如 api.bgm.tv"
            setText("i.pximg.net")
        }
        advancedBox.addView(
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
        advancedBox.addView(
            presets,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
        )
        // 指定 IP：留空 = 自动（自有网关 + 系统 DNS 各测一遍）；填了就只测这些地址（英文逗号分隔）
        ipInput = EditText(this).apply {
            hint = "指定 IP（留空=自动；可填多个，逗号分隔）"
            textSize = 12f
        }
        advancedBox.addView(
            ipInput,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
        )
        // 强制注入 ECH：留空 = 用 DoH 取到的 ech=；填了就用这一份（base64），可测"官方活值套到别的域名"
        echInput = EditText(this).apply {
            hint = "强制注入 ECH（base64，留空=用 DoH 的 ech=）"
            textSize = 10f
        }
        advancedBox.addView(
            echInput,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
        )
        // 详细探针按钮行放到输入框下面：主界面留给「一键体检」。
        // 按钮行必须显式 MATCH_PARENT：否则父行按 wrap_content 测量，
        // 里面 width=0 + weight=1 的按钮会被算成 0 宽（实测按钮完全不可见）。
        advancedBox.addView(bar, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        // TCP 层对照：原有的「原生测试」只跑 QUIC，对不支持 H3 的域名（hanime1.me 就是）等于没测。
        // 注意：这一行必须真的插进来——上一次脚本改代码时锚点没匹配、replace 静默跳过，
        // 只剩 setOnClickListener 引用未初始化的 lateinit，装完直接打不开（实测踩过）。
        btnTcp = Button(this).apply {
            text = "TCP 层对照（SNI 阻断 / IP 阻断 判定）"
            textSize = 12f
        }
        advancedBox.addView(
            btnTcp,
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
            // 首次打开自动跑一遍体检（用户最关心的就是这两个结论）
            btnNet.post { runNetworkCheck() }
        }
        val vf = File(filesDir, "last-verdict.txt")
        if (vf.exists()) ui { verdict.text = vf.readText() }

        btnNet.setOnClickListener { runNetworkCheck() }
        if (::btnTcp.isInitialized) btnTcp.setOnClickListener { runTcpCompare() }
        btnAdv.setOnClickListener {
            advancedBox.visibility = if (advancedBox.visibility == ViewGroup.GONE) ViewGroup.VISIBLE else ViewGroup.GONE
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

    // ---------------- TCP 层对照：区分「SNI 阻断」与「IP 层阻断」 ----------------

    private class TcpGroup(val label: String, val ip: String, val plain: TlsArm, val echArm: TlsArm?)

    /**
     * 探针原有的「原生测试」只跑 QUIC/H3 —— 对不支持 H3 的域名（hanime1.me 就是）等于没测。
     * 这里补 TCP 层对照：同一域名 × {网关 DoH IP, 系统 DNS IP} × {明文 SNI, 带 ECH}，
     * 用「明文通不通 ↔ 带 ECH 通不通」把两类阻断分开：
     *   明文不通 + ECH 通  → SNI 识别阻断（ECH 能救）
     *   明文不通 + ECH 不通 → IP 层阻断（ECH 救不了，只能换 IP）
     */
    private fun runTcpCompare() {
        btnTcp.isEnabled = false
        synchronized(log) { log.setLength(0) }
        ui { verdict.text = "TCP 层对照测试中…（约 20 秒）" }
        thread {
            try {
                val host = hostInput.text.toString().trim().ifEmpty { "hanime1.me" }
                val manualEch = echInput.text.toString().trim()
                say("===== TCP 层对照（不走 QUIC）=====")
                say("域名: $host")
                say("口径: 拿到 200 + trace = 通；sni=encrypted = ECH 真生效")
                say("目的: 明文通不通 ↔ 带 ECH 通不通 → 区分 SNI 阻断 / IP 层阻断")
                say("")
                val caPath = try { exportSystemCas() } catch (e: Exception) { say("[CA] 导出失败：" + e.message); "" }

                val gw = try { resolveViaGateway(host) } catch (e: Exception) { say("[DoH] 网关解析失败：" + e.message); null }
                val sysIps = try {
                    InetAddress.getAllByName(host).mapNotNull { it.hostAddress }.filter { it.isNotEmpty() }
                } catch (e: Exception) { say("[系统 DNS] 解析失败：" + e.message); emptyList() }

                val gwIp = gw?.first.orEmpty()
                val echVal = if (manualEch.isNotEmpty()) manualEch else gw?.second.orEmpty()
                say("网关 DoH IP : " + gwIp.ifEmpty { "解析失败 ✗" })
                say("系统 DNS IP : " + sysIps.joinToString(", ").ifEmpty { "解析失败 ✗" })
                say("ECH 来源    : " + when {
                    manualEch.isNotEmpty() -> "手动注入（${manualEch.length} 字符）"
                    echVal.isNotEmpty() -> "DoH 的 ech=（${echVal.length} 字符）"
                    else -> "无 —— 该域拿不到 ech=，只能测明文"
                })
                say("")

                val groups = mutableListOf<TcpGroup>()
                for ((label, ip) in listOf("网关 DoH IP" to gwIp, "系统 DNS IP" to sysIps.firstOrNull().orEmpty())) {
                    if (ip.isEmpty()) { say("---- $label：无可用地址，跳过 ----"); continue }
                    say("---- $label = $ip ----")
                    val p = probeTls(host, ip, "", caPath, "明文 SNI（无 ECH）")
                    val e = if (echVal.isNotEmpty()) probeTls(host, ip, echVal, caPath, "带 ECH") else null
                    if (e == null) say("    （该域没有 ech=，带 ECH 这臂跳过）")
                    groups += TcpGroup(label, ip, p, e)
                    say("")
                }

                say("======== TCP 层判定 ========")
                val sb = StringBuilder()
                for (g in groups) {
                    val pOk = g.plain.ok
                    val eOk = g.echArm?.ok == true
                    val eEnc = g.echArm?.sni == "encrypted"
                    val v = when {
                        g.echArm == null -> if (pOk) "✓ 明文可通（该域无 ech= 记录，测不了 ECH）"
                                            else "✗ 明文也不通：" + g.plain.err.take(60)
                        pOk && eOk -> "✓ 正常：明文与 ECH 都通" + if (eEnc) "，ECH 真生效" else "（但 sni=plaintext，ECH 没生效）"
                        !pOk && eOk -> "✓ 典型 SNI 阻断：明文被掐，带 ECH 就通 —— ECH 救回来了"
                        !pOk && !eOk -> "✗ IP 层阻断：明文和 ECH 都不通 —— ECH 救不了，只能换 IP"
                        else -> "⚠ 明文通、带 ECH 反而不通（ECH 被针对或 config 失效）"
                    }
                    say("  ${g.label}（$host @ ${g.ip}）: $v")
                    sb.append("${g.label}（${g.ip}）：").append(v).append('\n')
                }
                say("===========================")
                val text = "TCP 层对照 · $host\n" + sb.toString().trim()
                ui { verdict.text = text }
                try { File(filesDir, "last-verdict.txt").writeText(text) } catch (_: Throwable) {}
                finishRun("tcp-compare")
            } catch (t: Throwable) {
                say("[异常] " + t.message)
                finishRun("tcp-compare")
            }
        }
    }

    // ---------------- 主入口：本机网络能力体检（ECH / H3） ----------------

    /**
     * 只回答两个问题（结论直接写在 verdict 卡上，不用从日志里扒）：
     *  1) 本机当前网络能不能走 ECH —— 判据域 research.cloudflare.com（CF 自家 ECH 站点，自带 ech=，
     *     只支持 TCP 不支持 H3），看 /cdn-cgi/trace 的 sni 字段：
     *       sni=encrypted → ECH 真的被服务端解开；sni=plaintext → 没生效（等于不支持）。
     *     另跑一遍明文 SNI 作基线，用来区分"ECH 被针对"和"到 CF 的路本身就不通"。
     *  2) 本机当前网络能不能走 H3 —— 判据域 fbi.gov（支持 H3、无 ech=），强制 QUIC/H3
     *     （不依赖 Alt-Svc、绝不回落 TCP），拿到任何 HTTP 响应就算 H3 可用，再看 trace 的 http=http/3。
     *     附 TCP 对照，用来区分"UDP/443 被封"和"站点不给 H3"。
     */
    private class TlsArm(val ok: Boolean, val sni: String, val http: String, val hs: Long, val err: String)
    private class H3Arm(val ok: Boolean, val http: String, val hs: Long, val err: String)

    private fun traceField(body: String, key: String): String =
        body.lineSequence().firstOrNull { it.startsWith("$key=") }?.substringAfter("=")?.trim().orEmpty()

    private fun traceSummary2(body: String): String {
        if (body.isBlank()) return "(空)"
        val want = listOf("h=", "colo=", "http=", "sni=", "tls=")
        return body.lines().filter { l -> want.any { l.startsWith(it) } }.joinToString("  ")
    }

    private fun prefs() = getSharedPreferences("ech_h3_probe", MODE_PRIVATE)

    /** 默认 DoH 由构建时注入（CI secret）；公开构建为空，留给用户自己填 */
    private fun builtinDoh(): String = BuildConfig.DOH_URL

    private fun currentDoh(): String {
        val saved = prefs().getString("doh", "").orEmpty().trim()
        return if (saved.isNotEmpty()) saved else builtinDoh()
    }

    /** 当前接入方式（WiFi / 蜂窝） */
    private fun netType(): String = try {
        val cm = getSystemService(CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
        val n = cm.activeNetwork
        val caps = if (n != null) cm.getNetworkCapabilities(n) else null
        when {
            caps == null -> "未知"
            caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) -> "WiFi"
            caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR) -> "蜂窝"
            caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET) -> "有线"
            else -> "其他"
        }
    } catch (e: Exception) {
        "未知"
    }

    /** TCP + TLS1.3（echB64 为空 = 明文 SNI 对照臂），取一次 /cdn-cgi/trace */
    private fun probeTls(host: String, ip: String, echB64: String, caPath: String, label: String): TlsArm {
        say("  · $label")
        val t0 = System.currentTimeMillis()
        val json = try {
            ProbeNative.tlsEchFetch(host, ip, echB64, "/cdn-cgi/trace", caPath)
        } catch (t: Throwable) {
            say("    JNI 异常：" + t.message)
            return TlsArm(false, "", "", 0, "JNI 异常：" + t.message)
        }
        val wall = System.currentTimeMillis() - t0
        val o = try {
            JSONObject(json)
        } catch (t: Throwable) {
            return TlsArm(false, "", "", 0, "结果解析失败")
        }
        val err = o.optString("error", "")
        val hasErr = err.isNotEmpty() && err != "null"
        val body = o.optString("body", "")
        val sni = traceField(body, "sni")
        val http = traceField(body, "http")
        val hs = o.optLong("hs_ms")
        val ok = !hasErr && o.optInt("status") == 200
        say("    握手=${hs}ms tls=${o.optString("tls_version")} status=${o.optInt("status")} 墙钟=${wall}ms")
        say("    trace: " + traceSummary2(body))
        if (hasErr) say("    错误: " + err)
        return TlsArm(ok, sni, http, hs, if (hasErr) err else "")
    }

    /** 强制 QUIC/H3 取一次 /cdn-cgi/trace（拿到响应即握手成功） */
    private fun probeH3(host: String, ip: String, caPath: String, label: String): H3Arm {
        say("  · $label")
        val f = File(cacheDir, "netcheck-trace-h3.txt")
        if (f.exists()) f.delete()
        val json = try {
            ProbeNative.h3Fetch(host, ip, "", "/cdn-cgi/trace", "https://$host/", caPath, f.absolutePath)
        } catch (t: Throwable) {
            say("    JNI 异常：" + t.message)
            return H3Arm(false, "", 0, "JNI 异常：" + t.message)
        }
        val o = try {
            JSONObject(json)
        } catch (t: Throwable) {
            return H3Arm(false, "", 0, "结果解析失败")
        }
        val err = o.optString("error", "")
        val hasErr = err.isNotEmpty() && err != "null"
        val body = if (f.exists()) f.readText() else ""
        f.delete()
        val http = traceField(body, "http")
        val hs = o.optLong("hs_ms")
        val status = o.optInt("status")
        // 判定口径：拿到任何 HTTP 响应（哪怕 403/404）都算 H3 可用；只有握手被断/超时才算不可用。
        val ok = !hasErr && status > 0
        say("    握手=${hs}ms status=$status 总=${o.optLong("total_ms")}ms sent=${o.optLong("sent")} recv=${o.optLong("recv")}")
        say("    trace: " + traceSummary2(body))
        if (hasErr) say("    错误: " + err)
        return H3Arm(ok, http, hs, if (hasErr) err else "")
    }

    /** TCP 对照（系统 TLS 栈，只用来证明"TCP 通、UDP 不通"） */
    private fun tcpProbe(host: String): String = try {
        val c = (URL("https://$host/cdn-cgi/trace").openConnection() as HttpURLConnection).apply {
            connectTimeout = 8000
            readTimeout = 10000
        }
        val t = c.inputStream.bufferedReader().use { it.readText() }
        c.disconnect()
        t
    } catch (e: Exception) {
        "ERR " + e.message
    }

    private fun runNetworkCheck() {
        btnNet.isEnabled = false
        synchronized(log) { log.setLength(0) }
        ui { verdict.text = "检测中…（约 10 秒，别切后台）" }
        thread {
            try {
                val echHost = ECH_JUDGE_HOST
                val h3Host = H3_JUDGE_HOST
                say("== 本机网络能力检测（ECH / H3）==")
                say("时间 : " + SimpleDateFormat("MM-dd HH:mm:ss", Locale.CHINA).format(Date()))
                say("载体 : " + carrier())
                say("接入 : " + netType())
                say("网关 : " + currentDoh())
                say("版本 : " + BuildConfig.VERSION_NAME)
                if (currentDoh().isBlank()) {
                    say("[注意] 没有可用 DoH：ECH 判据拿不到 ech= 记录（展开「高级」填一个也行）")
                }
                say("")

                val caPath = try {
                    exportSystemCas()
                } catch (e: Exception) {
                    say("[CA] 导出失败：" + e.message)
                    ""
                }
                if (caPath.isNotEmpty()) say("[CA] 系统证书已导出（" + File(caPath).length() + " 字节）")

                // ---- 1) 解析两个判据域 ----
                val echRes = try {
                    resolveViaGateway(echHost)
                } catch (e: Exception) {
                    say("[DoH] $echHost 解析失败：" + e.message)
                    null
                }
                val h3Res = try {
                    resolveViaGateway(h3Host)
                } catch (e: Exception) {
                    say("[DoH] $h3Host 解析失败：" + e.message)
                    null
                }
                val echIp = echRes?.first.orEmpty()
                val echB64 = echRes?.second.orEmpty()
                val h3Ip = h3Res?.first.orEmpty()
                say(
                    "判据域 A（ECH）：$echHost → " +
                        (if (echIp.isEmpty()) "解析失败 ✗" else "$echIp｜ech= " +
                            (if (echB64.isEmpty()) "缺失 ✗" else echB64.length.toString() + " 字符 ✓"))
                )
                say("判据域 B（H3 ）：$h3Host → " + (if (h3Ip.isEmpty()) "解析失败 ✗" else h3Ip))
                say("")

                // ---- 2) ECH ----
                say("---- ECH 检测：$echHost（自带 ech=，仅 TCP）----")
                val base = if (echIp.isNotEmpty()) {
                    probeTls(echHost, echIp, "", caPath, "基线：明文 SNI（无 ECH）")
                } else {
                    TlsArm(false, "", "", 0, "无可用地址")
                }
                val arms = mutableListOf<TlsArm>()
                if (echIp.isNotEmpty() && echB64.isNotEmpty()) {
                    for (i in 1..2) arms += probeTls(echHost, echIp, echB64, caPath, "带 ECH 第 $i 次")
                }
                val encCount = arms.count { it.sni == "encrypted" }
                val encOk = arms.count { it.ok && it.sni == "encrypted" }
                val plainOk = arms.count { it.ok && it.sni == "plaintext" }
                val echo = when {
                    echIp.isEmpty() || echB64.isEmpty() ->
                        Triple("?", "无法判定", "判据域不可用（拿不到地址或 ech= 记录），无法发起 ECH")
                    encOk > 0 ->
                        Triple(
                            "✓", "支持",
                            "ECH 真正生效：sni=encrypted（$encCount/${arms.size} 次，握手 " +
                                arms.first { it.ok && it.sni == "encrypted" }.hs + "ms）"
                        )
                    plainOk > 0 ->
                        Triple("✗", "不支持", "带 ECH 握手成功，但服务端只看到明文 SNI（sni=plaintext）→ ECH 未被解密")
                    !base.ok ->
                        Triple("✗", "不支持", "到该判据域的 TCP/TLS 本身不通（" + base.err.take(50) + "）→ 网络层面阻断")
                    else ->
                        Triple(
                            "✗", "不支持",
                            "带 ECH 握手被阻断（" + (arms.lastOrNull()?.err ?: "").take(50) + "），而明文 SNI 基线正常 → 针对性阻断"
                        )
                }
                val echMark = echo.first
                val echWord = echo.second
                val echWhy = echo.third
                say("")

                // ---- 3) H3 ----
                say("---- H3 检测：$h3Host（支持 H3、无 ech=）----")
                val h3Arms = mutableListOf<H3Arm>()
                if (h3Ip.isNotEmpty()) {
                    for (i in 1..2) h3Arms += probeH3(h3Host, h3Ip, caPath, "强制 H3 第 $i 次")
                }
                val tcpBody = tcpProbe(h3Host)
                say("  · TCP 对照： " + traceSummary2(tcpBody))
                val h3Good = h3Arms.count { it.ok && it.http == "http/3" }
                val h3Resp = h3Arms.count { it.ok }
                val h3vo = when {
                    h3Ip.isEmpty() ->
                        Triple("?", "无法判定", "判据域解析不到地址")
                    h3Good > 0 ->
                        Triple(
                            "✓", "支持",
                            "H3 可用：拿到 http/3 响应（$h3Good/${h3Arms.size} 次，握手 " +
                                h3Arms.first { it.ok }.hs + "ms）"
                        )
                    h3Resp > 0 ->
                        Triple("?", "无法判定", "H3 握手成功但 trace 未报 http/3（响应异常）")
                    else ->
                        Triple(
                            "✗", "不支持",
                            "H3 不可用：" + (h3Arms.lastOrNull()?.err ?: "握手失败").take(60) +
                                (if (tcpBody.startsWith("ERR")) "；TCP 对照也不通 → 整体网络到不了该域"
                                else "；TCP 对照正常 → 多为 UDP/443 被阻断或限速")
                        )
                }
                val h3Mark = h3vo.first
                val h3Word = h3vo.second
                val h3Why = h3vo.third

                // ---- 4) 结论 ----
                val sb = StringBuilder()
                sb.append("检测时间 ").append(SimpleDateFormat("MM-dd HH:mm", Locale.CHINA).format(Date())).append('\n')
                sb.append("接入 ").append(netType()).append(" · ").append(carrier().substringBefore(" 卡=")).append("\n")
                sb.append('\n')
                sb.append("ECH  ").append(echMark).append(' ').append(echWord).append('\n')
                sb.append("      ").append(echWhy).append('\n')
                sb.append('\n')
                sb.append("H3   ").append(h3Mark).append(' ').append(h3Word).append('\n')
                sb.append("      ").append(h3Why).append('\n')
                sb.append('\n')
                sb.append(
                    when {
                        echMark == "✓" && h3Mark == "✓" -> "结论：当前网络可走 ECH + H3（两条都能用）"
                        echMark == "✓" -> "结论：当前网络可走 ECH，H3 不可用（走 TCP+ECH）"
                        h3Mark == "✓" -> "结论：当前网络 H3 可用，ECH 不可用（H3 下 SNI 仍可能暴露）"
                        else -> "结论：当前网络 ECH / H3 都不可用"
                    }
                )
                val text = sb.toString()
                ui { verdict.text = text }
                File(filesDir, "last-verdict.txt").writeText(text)
                say("")
                say("============= 结论汇总 =============")
                say(text)
                say("===================================")
                say("== 结束 ==")
                finishRun("net-check")
            } catch (t: Throwable) {
                say("检测异常：" + t)
                finishRun("net-check-error")
            }
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
                say("网关 : " + currentDoh())
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
                // 指定 IP 优先：填了就完全按用户给的地址测（覆盖两种自动来源）
                val manualIps = ipInput.text.toString().split(',', '，')
                    .map { it.trim() }.filter { it.isNotEmpty() }
                val sources = LinkedHashMap<String, String>()
                if (manualIps.isNotEmpty()) {
                    manualIps.forEachIndexed { i, ip -> sources["指定 IP #" + (i + 1)] = ip }
                } else {
                    gateway?.first?.let { sources["网关（自有 DoH）"] = it }
                    runCatching {
                        InetAddress.getAllByName(host)
                            .filterIsInstance<Inet4Address>()
                            .map { it.hostAddress }
                            .take(2)
                    }.getOrNull()?.forEach { sources["系统原生 DNS"] = it }
                }
                // 强制注入 ECH：填了就用这一份（base64），否则用 DoH 取到的 ech=
                val manualEch = echInput.text.toString().replace(Regex("\\s"), "")
                val echB64 = if (manualEch.isNotEmpty()) manualEch else gateway?.second.orEmpty()
                val echFrom = if (manualEch.isNotEmpty()) "手动注入（强制）" else "DoH 的 ech="
                if (sources.isEmpty()) {
                    say("== 结束（无可用地址：请填指定 IP，或检查域名）==")
                    finishRun("probe-run")
                    return@thread
                }
                // App 的实际策略：ECH 不用目标域自己的记录，而取 CF 官方 cloudflare-ech.com 的活值（经自有网关查），
                // 再注入到目标域。这样目标域记录过期/被拒也能连上（App 里就是这么做的）。
                val officialEch = try {
                    resolveViaGateway("cloudflare-ech.com").second
                } catch (e: Exception) {
                    say("[ECH ] cloudflare-ech.com 活值获取失败：" + e.message)
                    ""
                }
                say("[模式] 强制 H3：不依赖 Alt-Svc，直接起 QUIC/H3")
                say("[ECH ] CF 官方活值：" + (if (officialEch.isEmpty()) "获取失败 ✗" else officialEch.length.toString() + " 字符 ✓"))
                sources.forEach { (label, ip) -> say("[地址] $label → $ip") }
                say("[ECH ] $echFrom：" + (if (echB64.isEmpty()) "无（将走明文 SNI）✗" else echB64.length.toString() + " 字符 ✓"))
                say("")

                val realPath = if (host.endsWith("pximg.net")) imgPath else "/"
                val referer = if (host.endsWith("pximg.net")) "https://www.pixiv.net/" else "https://$host/"

              // 判定口径：拿到 HTTP 响应（哪怕 403/404）就算握手成功 = 这条路径支持 H3；
              // 握手被断/超时 = 不支持。带 ECH 与不带 ECH 分开记，才能分辨"是不是 ECH 的锅"。
              val verdicts = mutableListOf<String>()
              for ((srcLabel, ip) in sources) {
                say("########## 来源：$srcLabel（$ip）##########")
                // 关键对照：带 ECH 与 不带 ECH（明文 SNI）
                // 三组对照：目标域自带 / CF 官方活值（＝App 策略）/ 明文 SNI
                val arms = ArrayList<Pair<String, String>>()
                if (echB64.isNotEmpty()) {
                    arms += (if (manualEch.isNotEmpty()) "带 ECH（手动注入）" else "带 ECH（目标域自带）") to echB64
                }
                if (officialEch.isNotEmpty()) {
                    arms += "带 ECH（CF 官方活值＝App 策略）" to officialEch
                }
                arms += "无 ECH（明文 SNI）" to ""
                for ((armName, armEch) in arms) {
                    say("===== [$srcLabel] $armName =====")
                    var okCount = 0
                    var hsSum = 0L
                    var totalSum = 0L
                    var lastStatus = 0
                    var lastErr = ""
                    for (i in 1..3) {
                        say("---- $armName 第 $i 次 ----")
                        val t0 = System.currentTimeMillis()
                        val json = try {
                            ProbeNative.h3Fetch(host, ip, armEch, realPath, referer, caPath, "")
                        } catch (t: Throwable) {
                            say("JNI 异常：" + t.message)
                            lastErr = "JNI 异常：" + t.message
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
                        if (err.isNotEmpty() && err != "null") {
                            lastErr = err
                        } else {
                            okCount++
                            hsSum += o.optLong("hs_ms")
                            totalSum += o.optLong("total_ms")
                            lastStatus = o.optInt("status")
                        }
                    }
                    verdicts += if (okCount > 0) {
                        "✓ [$srcLabel] $armName：H3 可用（成功 " + okCount + "/3，平均握手 " + (hsSum / okCount) +
                                "ms，平均总耗时 " + (totalSum / okCount) + "ms，状态 " + lastStatus + "）"
                    } else {
                        "✗ [$srcLabel] $armName：H3 不可用（0/3）" + (if (lastErr.isEmpty()) "" else "；末次错误：" + lastErr)
                    }
                }
              }
                say("")
                say("============= 结论汇总 =============")
                say("域名：" + host)
                say("ECH ：" + echFrom + "（" + (if (echB64.isEmpty()) "无 → 走明文 SNI" else echB64.length.toString() + " 字符") + "）")
                verdicts.forEach { say(it) }
                // 单独给一条"App 实际链路"的判定：自有网关 IP + CF 官方活值 ECH + 主动 H3 —— 这才是 App 会走的组合
                val appVerdict = verdicts.firstOrNull { it.contains("App 策略") }
                say(
                    when {
                        appVerdict == null -> "App 策略判定：未取到 CF 官方活值，无法评估 ✗"
                        appVerdict.startsWith("✓") -> "App 策略判定（网关 IP + CF 官方活值 + 主动 H3）：本域名【可用】✓"
                        else -> "App 策略判定（网关 IP + CF 官方活值 + 主动 H3）：本域名【不可用】✗"
                    }
                )
                say(
                    if (verdicts.any { it.startsWith("✓") })
                        "判定：以上覆盖到的路径里有【支持 H3】的组合，可考虑启用 H3。"
                    else
                        "判定：以上路径全部【不支持 H3】，应走 TCP（ECH 照旧）。"
                )
                say("===================================")
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
        upload(event, mapOf("log" to currentLog(), "gateway" to currentDoh()))
        ui {
            btn.isEnabled = true; btnWv.isEnabled = true; btnNet.isEnabled = true
            if (::btnTcp.isInitialized) btnTcp.isEnabled = true
        }
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
                root.addView(w)
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
        ui { btn.isEnabled = true; btnWv.isEnabled = true; btnNet.isEnabled = true }
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
        if (currentDoh().isBlank()) {
            say("需要先配置 DoH 地址（展开「高级」填一个再点）")
            return
        }
        val gwHost = currentDoh().substringAfter("https://").substringBefore("/")
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
            val url = URL(currentDoh() + "?name=" + host + "&type=" + type)
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
        /** ECH 判据域：CF 自家站点，自带 ech= 记录，只支持 TCP（实测 H3 握手被拒 no_application_protocol） */
        const val ECH_JUDGE_HOST = "research.cloudflare.com"
        /** H3 判据域：支持 H3，无 ech= 记录（ECH 与 H3 分开测，互不干扰） */
        const val H3_JUDGE_HOST = "fbi.gov"
    }
}
