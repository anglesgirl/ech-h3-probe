package com.anglesgirl.echh3probe

/** Rust 侧（quiche + 打过 ECH 补丁的 BoringSSL） */
object ProbeNative {
    init {
        // 构建铁律：只有主库，且符号用 llvm-nm -D 验过
        System.loadLibrary("ech_h3_probe")
    }

    /**
     * @param echB64  ECHConfigList 的 base64（空串 = 不带 ECH）
     * @param caPath  系统 CA 导出的 PEM 文件（比读 /system 目录可靠）
     * @return JSON：ok/hs_ms/status/first_byte_ms/total_ms/body_len/alpn/ech_override/sent/recv/peer_err/error
     */
    external fun h3Fetch(
        host: String,
        peerIp: String,
        echB64: String,
        path: String,
        referer: String,
        caPath: String,
        outFile: String,
    ): String
}
