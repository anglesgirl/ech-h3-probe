//! 桌面版探针（与安卓 JNI 共用同一份核心逻辑）
//!
//! 用法: probe <host> <peer_ip> [none|garbage|file:<路径>] [path] [referer] [ca文件]

use ech_h3_probe::h3_fetch;
use std::time::Duration;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let host = a
        .get(1)
        .cloned()
        .unwrap_or_else(|| "cloudflare-ech.com".into());
    let ip = a.get(2).cloned().expect("需要 peer_ip");
    let mode = a.get(3).cloned().unwrap_or_else(|| "none".into());
    let path = a.get(4).cloned().unwrap_or_else(|| "/".into());
    let referer = a.get(5).cloned().filter(|s| !s.is_empty());
    let ca = a
        .get(6)
        .cloned()
        .unwrap_or_else(|| "/etc/ssl/certs/ca-certificates.crt".into());

    let ech: Option<Vec<u8>> = match mode.as_str() {
        "none" => None,
        "garbage" => Some(vec![0x00, 0x01, 0x00, 0x02, 0xde, 0xad]),
        m if m.starts_with("file:") => Some(std::fs::read(&m[5..]).expect("读 ECH 文件失败")),
        other => panic!("未知模式 {}", other),
    };

    println!("host={} ip={} mode={} path={}", host, ip, mode, path);
    let o = h3_fetch(
        &host,
        &ip,
        ech.as_deref(),
        &path,
        referer.as_deref(),
        &ca,
        Duration::from_secs(8),
        Duration::from_secs(25),
    );
    println!(
        "诊断三件套 : sent={} recv={} peer_err={}",
        o.sent,
        o.recv,
        if o.peer_err.is_empty() {
            "-"
        } else {
            &o.peer_err
        }
    );
    println!(
        "握手        : {} ms, established={}, alpn={:?}",
        o.hs_ms, o.established, o.alpn
    );
    println!(
        "ECH         : override={:?}, retry_len={}",
        o.ech_override, o.ech_retry_len
    );
    println!(
        "HTTP/3      : status={} 首字节={}ms 总耗时={}ms 字节={}",
        o.status, o.first_byte_ms, o.total_ms, o.body_len
    );
    println!("响应头      : cf-ray={} server={}", o.cf_ray, o.server);
    if let Some(e) = &o.error {
        println!("错误        : {}", e);
        std::process::exit(1);
    }
}
