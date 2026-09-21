# ECH / H3 真机探针

一个只做一件事的安卓小工具：**判断你当前所在的网络（WiFi / 蜂窝）到底能不能走 ECH、能不能走 H3。**

「能不能用 ECH」不是域名或 App 的属性，而是**你当前这一段网络**的属性：有的网络掐 UDP/443（H3 直接没了），
有的中间盒会把 ECH 剥掉（SNI 又暴露了）。这个探针把这两件事各测一次，直接给结论，不用去读一面墙的日志。

## 判据域

| 能力 | 判据 | 为什么是它 |
|---|---|---|
| **ECH** | `https://research.cloudflare.com/cdn-cgi/trace` | CF 自家 ECH 站点，HTTPS 记录自带 `ech=`；但它**不支持 H3**（QUIC 握手直接被拒 `no_application_protocol`），所以只能走 TCP —— 正好与 H3 解耦 |
| **H3**  | `https://fbi.gov/cdn-cgi/trace` | 支持 H3，且没有 `ech=` 记录，与 ECH 完全分开 |

## 判定口径

**ECH（TCP + TLS1.3 + ECH）**

看 `/cdn-cgi/trace` 返回的 `sni=`：

- `sni=encrypted` → ECH **真的被服务端解开**，才算支持；
- `sni=plaintext` → 没生效（哪怕握手成功，也等于不支持）。

同时另跑一条**明文 SNI 基线**，用来区分两种情况：

- 基线正常、带 ECH 被断 → ECH 被针对性阻断；
- 基线也不通 → 是到 Cloudflare 的路本身不通（网络层面阻断），跟 ECH 无关。

**H3（强制 QUIC/H3，不依赖 Alt-Svc、绝不回落 TCP）**

- **拿到任何 HTTP 响应（哪怕 403/404）就算握手成功** = 这条路径支持 H3，再看 trace 的 `http=http/3`；
- 只有握手被断/超时才算不支持；
- 附一条 TCP 对照，用来区分「UDP/443 被封」和「站点不给 H3」。

## 怎么用

装 APK → 打开 → 点「检测本机网络（ECH / H3）」，约 10 秒出结论：

```
检测时间 09-21 19:30
接入 WiFi · 网络=中国移动[46000→移动]

ECH  ✓ 支持
      ECH 真正生效：sni=encrypted（2/2 次，握手 12ms）

H3   ✗ 不支持
      H3 不可用：握手超时；TCP 对照正常 → 多为 UDP/443 被阻断或限速

结论：当前网络可走 ECH，H3 不可用（走 TCP+ECH）
```

结论同时落盘（`filesDir/last-verdict.txt`），崩溃或误退都不丢；下面的日志区是逐次明细。

「高级：对照测试」里可以指定任意域名、指定 IP、强制注入 ECH（base64），做更细的对照实验。

## DoH 地址

ECH 判据要读 HTTPS 里的 `ech=` 记录，这需要一个 DoH 解析器。**本仓库不内置任何网关地址**：
默认值在构建时通过环境变量 `ECH_DOH_URL` 注入；自己编译的版本请在「高级」里填一个你自己的 DoH 地址
（填过会保存，重启仍生效）。没配 DoH 时，ECH 判据会如实报「无法判定」，而不会瞎给结论。

## 自己编译

需要 Android SDK/NDK + Rust。CI 见 `.github/workflows/android.yml`：

1. 从 crates.io 取 quiche 0.22 源码到 `rust/vendor/quiche`，跑 `tools/patch_quiche.py`
   把 BoringSSL 的 ECH 客户端入口暴露出来（约 40 行，逐条断言命中次数）；
2. `cargo ndk` 编 arm64-v8a / armeabi-v7a，只留主库并校验 JNI 符号；
3. Gradle 打 APK（默认 DoH 由 `ECH_DOH_URL` 注入）。

## 实现要点（踩过的坑）

- **ECH over TCP**：直接对 quiche vendored 的**同一份** BoringSSL 写裸 FFI（`SSL_set1_ech_config_list`
  等），不引 `boring` / `boring-sys` —— 否则会编出第二份 BoringSSL，CI 白烧十几分钟。
- **BoringSSL 与 OpenSSL 的一个行为差异**：`X509_check_host` / `X509_VERIFY_PARAM_set1_host`
  **不把 `chklen=0` 当 `strlen()` 处理**，必须显式传长度，否则永远判「证书不匹配」。
- **H3**：quiche + 打过 ECH 补丁的 BoringSSL，ALPN 用裸名 `h3`；判定以「有没有拿到 HTTP 响应」为准。
- WebView 那条路只用来验证「首连是否被 TCP RST」，与上面的原生通道互不影响。
