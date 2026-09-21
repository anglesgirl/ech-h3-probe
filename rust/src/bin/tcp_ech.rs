//! 桌面版 TLS+ECH 探针（与安卓 JNI 共用同一份 tls_ech 逻辑）
//!
//! 用法: tcp_ech <host> <peer_ip> [none|file:<ech文件>] [path] [ca文件]

use std::time::Duration;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let host = a
        .get(1)
        .cloned()
        .unwrap_or_else(|| "research.cloudflare.com".into());
    let ip = a.get(2).cloned().expect("需要 peer_ip");
    let mode = a.get(3).cloned().unwrap_or_else(|| "none".into());
    let path = a.get(4).cloned().unwrap_or_else(|| "/cdn-cgi/trace".into());
    let ca = a
        .get(5)
        .cloned()
        .unwrap_or_else(|| "/etc/ssl/certs/ca-certificates.crt".into());

    let ech: Option<Vec<u8>> = match mode.as_str() {
        "none" => None,
        m if m.starts_with("file:") => Some(std::fs::read(&m[5..]).expect("读 ECH 文件失败")),
        other => panic!("未知模式 {}", other),
    };

    println!("host={} ip={} mode={} path={}", host, ip, mode, path);
    let o = ech_h3_probe::tls_ech::tls_ech_fetch(
        &host,
        &ip,
        ech.as_deref(),
        &path,
        &ca,
        Duration::from_secs(8),
        Duration::from_secs(10),
    );
    println!(
        "握手   : {} ms established={} tls={} alpn={:?}",
        o.hs_ms, o.established, o.tls_version, o.alpn
    );
    println!(
        "ECH    : override={:?} retry_len={}",
        o.ech_override, o.ech_retry_len
    );
    println!(
        "HTTP   : status={} 总耗时={}ms 字节={}",
        o.status, o.total_ms, o.body_len
    );
    println!("--- body ---\n{}", o.body);
    if let Some(e) = &o.error {
        println!("错误   : {}", e);
        std::process::exit(1);
    }
}
