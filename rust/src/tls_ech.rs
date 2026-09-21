//! TLS 1.3 + ECH（走 TCP）—— 给不支持 H3 的站点用（典型：research.cloudflare.com）。
//!
//! 与 h3 那条路共用同一份：quiche vendored 的 BoringSSL（`libssl.a` 里
//! `SSL_set1_ech_config_list` 等 ECH 客户端入口都在），所以这里只写裸 FFI 声明，
//! 不额外引入 boring/boring-sys（否则会编出第二份 BoringSSL，CI 白烧十分钟）。

use std::ffi::CString;

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

#[allow(non_camel_case_types, dead_code)]
mod bssl {
    use super::*;

    #[repr(C)]
    pub struct SSL_CTX {
        _private: [u8; 0],
    }
    #[repr(C)]
    pub struct SSL {
        _private: [u8; 0],
    }
    #[repr(C)]
    pub struct SSL_METHOD {
        _private: [u8; 0],
    }
    #[repr(C)]
    pub struct X509 {
        _private: [u8; 0],
    }

    extern "C" {
        pub fn TLS_client_method() -> *const SSL_METHOD;
        pub fn SSL_CTX_new(m: *const SSL_METHOD) -> *mut SSL_CTX;
        pub fn SSL_CTX_free(c: *mut SSL_CTX);
        pub fn SSL_CTX_load_verify_locations(
            c: *mut SSL_CTX,
            file: *const c_char,
            dir: *const c_char,
        ) -> c_int;
        pub fn SSL_CTX_set_verify(c: *mut SSL_CTX, mode: c_int, cb: *mut c_void);
        pub fn SSL_new(c: *mut SSL_CTX) -> *mut SSL;
        pub fn SSL_free(s: *mut SSL);
        pub fn SSL_set_fd(s: *mut SSL, fd: c_int) -> c_int;
        pub fn SSL_set_tlsext_host_name(s: *mut SSL, name: *const c_char) -> c_int;
        pub fn SSL_get0_param(s: *mut SSL) -> *mut c_void;
        pub fn SSL_get_peer_certificate(s: *const SSL) -> *mut X509;
        pub fn X509_free(x: *mut X509);
        pub fn X509_check_host(
            x: *mut X509,
            chk: *const c_char,
            chklen: usize,
            flags: c_uint,
            peername: *mut *mut c_char,
        ) -> c_int;
        pub fn X509_VERIFY_PARAM_set1_host(
            param: *mut c_void,
            name: *const c_char,
            namelen: usize,
        ) -> c_int;
        pub fn SSL_set1_ech_config_list(s: *mut SSL, list: *const u8, len: usize) -> c_int;
        pub fn SSL_get0_ech_name_override(
            s: *const SSL,
            out_name: *mut *const c_char,
            out_len: *mut usize,
        );
        pub fn SSL_get0_ech_retry_configs(
            s: *const SSL,
            out_retry: *mut *const u8,
            out_len: *mut usize,
        );
        pub fn SSL_connect(s: *mut SSL) -> c_int;
        pub fn SSL_write(s: *mut SSL, buf: *const u8, n: c_int) -> c_int;
        pub fn SSL_read(s: *mut SSL, buf: *mut u8, n: c_int) -> c_int;
        pub fn SSL_get_error(s: *const SSL, ret: c_int) -> c_int;
        pub fn SSL_get_version(s: *const SSL) -> *const c_char;
        pub fn SSL_get0_alpn_selected(s: *const SSL, data: *mut *const u8, len: *mut c_uint);
        pub fn ERR_get_error() -> c_uint;
        pub fn ERR_error_string_n(e: c_uint, buf: *mut c_char, len: usize);
    }

    pub const SSL_VERIFY_PEER: c_int = 1;
    pub const SSL_ERROR_WANT_READ: c_int = 2;
    pub const SSL_ERROR_WANT_WRITE: c_int = 3;
    pub const SSL_ERROR_SYSCALL: c_int = 5;
    pub const SSL_ERROR_ZERO_RETURN: c_int = 6;
}

/// 取出 BoringSSL 错误队列（一条都不许吞：ECH 失败的原因全在这儿）
fn drain_errors() -> String {
    let mut out = String::new();
    unsafe {
        loop {
            let e = bssl::ERR_get_error();
            if e == 0 {
                break;
            }
            let mut buf = [0 as c_char; 256];
            bssl::ERR_error_string_n(e, buf.as_mut_ptr(), buf.len());
            let c = std::ffi::CStr::from_ptr(buf.as_ptr())
                .to_string_lossy()
                .to_string();
            if !out.is_empty() {
                out.push_str(" | ");
            }
            out.push_str(&c);
            if out.len() > 800 {
                break;
            }
        }
    }
    out
}

/// 一次 TLS+ECH 请求的全部可观测结果
pub struct TlsOutcome {
    pub hs_ms: u128,
    pub established: bool,
    pub tls_version: String,
    pub alpn: String,
    /// ECH 被服务端拒绝时给出的 public name（为空 = ECH 被接受）
    pub ech_override: Option<String>,
    pub ech_retry_len: usize,
    pub status: u16,
    pub total_ms: u128,
    pub body_len: usize,
    pub body: String,
    pub error: Option<String>,
}

impl TlsOutcome {
    fn err(msg: String) -> Self {
        TlsOutcome {
            hs_ms: 0,
            established: false,
            tls_version: String::new(),
            alpn: String::new(),
            ech_override: None,
            ech_retry_len: 0,
            status: 0,
            total_ms: 0,
            body_len: 0,
            body: String::new(),
            error: Some(msg),
        }
    }
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap_or_default()
}

/// 向 host 发起一次 TLS1.3 GET（TCP 连到 peer_ip，SNI/证书校验用 host）。
pub fn tls_ech_fetch(
    host: &str,
    peer_ip: &str,
    ech: Option<&[u8]>,
    path: &str,
    ca_path: &str,
    connect_timeout: Duration,
    request_timeout: Duration,
) -> TlsOutcome {
    let ip: IpAddr = match peer_ip.parse() {
        Ok(a) => a,
        Err(e) => return TlsOutcome::err(format!("peer_ip 解析失败: {}", e)),
    };
    let peer = SocketAddr::new(ip, 443);
    let tcp = match TcpStream::connect_timeout(&peer, connect_timeout) {
        Ok(t) => t,
        Err(e) => return TlsOutcome::err(format!("TCP 连接失败: {}", e)),
    };
    let _ = tcp.set_read_timeout(Some(Duration::from_millis(1500)));
    let _ = tcp.set_write_timeout(Some(Duration::from_millis(5000)));
    let _ = tcp.set_nodelay(true);

    let host_c = cstr(host);
    let ca_c = cstr(ca_path);
    let t0 = Instant::now();

    unsafe {
        let method = bssl::TLS_client_method();
        let ctx = bssl::SSL_CTX_new(method);
        if ctx.is_null() {
            return TlsOutcome::err("SSL_CTX_new 失败".to_string());
        }
        let ssl = bssl::SSL_new(ctx);
        if ssl.is_null() {
            bssl::SSL_CTX_free(ctx);
            return TlsOutcome::err("SSL_new 失败".to_string());
        }
        // 用后统一释放（RAII 守卫）
        struct Guard(*mut bssl::SSL, *mut bssl::SSL_CTX);
        impl Drop for Guard {
            fn drop(&mut self) {
                unsafe {
                    bssl::SSL_free(self.0);
                    bssl::SSL_CTX_free(self.1);
                }
            }
        }
        let _guard = Guard(ssl, ctx);

        if bssl::SSL_CTX_load_verify_locations(ctx, ca_c.as_ptr(), std::ptr::null()) != 1 {
            // 加载失败退化为无验证是 fail-open，坚决不允许：直接报错
            return TlsOutcome::err(format!("加载 CA 失败({}): {}", ca_path, drain_errors()));
        }
        bssl::SSL_CTX_set_verify(ctx, bssl::SSL_VERIFY_PEER, std::ptr::null_mut());

        if bssl::SSL_set_fd(ssl, tcp.as_raw_fd()) != 1 {
            return TlsOutcome::err(format!("SSL_set_fd 失败: {}", drain_errors()));
        }
        if bssl::SSL_set_tlsext_host_name(ssl, host_c.as_ptr()) != 1 {
            return TlsOutcome::err(format!("设置 SNI 失败: {}", drain_errors()));
        }
        // 证书必须对该 host 有效（ECH 下真实 SNI 也在内层，校验目标不变）。
        // 不用 X509_VERIFY_PARAM_set1_host：实测它在 quiche vendored 的这份 BoringSSL 上
        // 返回 0（非 1）却无错误入队，语义不可信；改为握手后拿对端证书手工 X509_check_host，
        // 返回值明确（1=匹配）。
        if let Some(list) = ech {
            if !list.is_empty()
                && bssl::SSL_set1_ech_config_list(ssl, list.as_ptr(), list.len()) != 1
            {
                return TlsOutcome::err(format!("注入 ECHConfigList 失败: {}", drain_errors()));
            }
        }

        // ---- 握手 ----
        let hs_rc = bssl::SSL_connect(ssl);
        let hs_ms = t0.elapsed().as_millis();
        let mut out = TlsOutcome {
            hs_ms,
            established: hs_rc == 1,
            tls_version: String::new(),
            alpn: String::new(),
            ech_override: None,
            ech_retry_len: 0,
            status: 0,
            total_ms: 0,
            body_len: 0,
            body: String::new(),
            error: None,
        };
        if hs_rc != 1 {
            let e = bssl::SSL_get_error(ssl, hs_rc);
            let detail = drain_errors();
            out.error = Some(format!(
                "TLS 握手失败: SSL_get_error={} {}{}",
                e,
                if detail.is_empty() {
                    "(无 ERR 记录)".to_string()
                } else {
                    detail
                },
                if e == bssl::SSL_ERROR_SYSCALL {
                    "（多为对端 RST/连接被掐）"
                } else {
                    ""
                }
            ));
            return out;
        }
        // 握手后校验对端证书确实签给 host（链校验已由 SSL_VERIFY_PEER 完成）
        let cert = bssl::SSL_get_peer_certificate(ssl);
        if cert.is_null() {
            out.error = Some("对端未提供证书".to_string());
            return out;
        }
        // 注意：BoringSSL 的 X509_check_host **不会**把 chklen=0 当 strlen 处理（与 OpenSSL 不同，
        // 它直接按 0 长度比较 → 永远不匹配），必须显式传长度。
        let crc = bssl::X509_check_host(
            cert,
            host_c.as_ptr(),
            host.len(),
            0,
            std::ptr::null_mut(),
        );
        bssl::X509_free(cert);
        if crc != 1 {
            out.error = Some(format!("证书与 {} 不匹配（X509_check_host={}）", host, crc));
            return out;
        }
        out.tls_version = unsafe_cstr(bssl::SSL_get_version(ssl));
        {
            let mut p: *const u8 = std::ptr::null();
            let mut l: c_uint = 0;
            bssl::SSL_get0_alpn_selected(ssl, &mut p, &mut l);
            if !p.is_null() && l > 0 {
                out.alpn =
                    String::from_utf8_lossy(std::slice::from_raw_parts(p, l as usize)).to_string();
            }
        }
        {
            let mut p: *const c_char = std::ptr::null();
            let mut l: usize = 0;
            bssl::SSL_get0_ech_name_override(ssl, &mut p, &mut l);
            if !p.is_null() && l > 0 {
                out.ech_override = Some(
                    String::from_utf8_lossy(std::slice::from_raw_parts(p as *const u8, l))
                        .to_string(),
                );
            }
        }
        {
            let mut p: *const u8 = std::ptr::null();
            let mut l: usize = 0;
            bssl::SSL_get0_ech_retry_configs(ssl, &mut p, &mut l);
            out.ech_retry_len = if p.is_null() { 0 } else { l };
        }

        // ---- 请求 ----
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            path, host
        );
        let mut off = 0usize;
        let rb = req.as_bytes();
        while off < rb.len() {
            let n = bssl::SSL_write(ssl, rb[off..].as_ptr(), (rb.len() - off) as c_int);
            if n <= 0 {
                out.error = Some(format!("SSL_write 失败: {}", drain_errors()));
                return out;
            }
            off += n as usize;
        }

        // ---- 读响应（Connection: close，读到 EOF 或超时）----
        let mut raw: Vec<u8> = Vec::new();
        let mut buf = [0u8; 8192];
        let read_start = Instant::now();
        loop {
            let n = bssl::SSL_read(ssl, buf.as_mut_ptr(), buf.len() as c_int);
            if n > 0 {
                raw.extend_from_slice(&buf[..n as usize]);
                if raw.len() > 512 * 1024 {
                    break;
                }
                continue;
            }
            let e = bssl::SSL_get_error(ssl, n);
            if e == bssl::SSL_ERROR_ZERO_RETURN {
                break;
            }
            if e == bssl::SSL_ERROR_WANT_READ || e == bssl::SSL_ERROR_WANT_WRITE {
                if read_start.elapsed() > request_timeout {
                    out.error = Some("读响应超时".to_string());
                    break;
                }
                continue;
            }
            if e == bssl::SSL_ERROR_SYSCALL {
                if n == 0 {
                    break; // 对端正常关连接
                }
                if read_start.elapsed() > request_timeout {
                    out.error = Some("读响应超时（syscall）".to_string());
                } else {
                    out.error = Some(format!("SSL_read 失败: {}", drain_errors()));
                }
                break;
            }
            out.error = Some(format!(
                "SSL_read 错误 SSL_get_error={} {}",
                e,
                drain_errors()
            ));
            break;
        }
        out.total_ms = t0.elapsed().as_millis();
        out.body_len = raw.len();
        let text = String::from_utf8_lossy(&raw).to_string();
        out.status = parse_status(&text);
        out.body = split_body(&text);
        if out.status == 0 && out.error.is_none() {
            out.error = Some(format!("未解析到 HTTP 状态行（收到 {} 字节）", raw.len()));
        }
        out
    }
}

unsafe fn unsafe_cstr(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        std::ffi::CStr::from_ptr(p).to_string_lossy().to_string()
    }
}

fn parse_status(resp: &str) -> u16 {
    let first = resp.lines().next().unwrap_or("");
    let mut it = first.split_whitespace();
    let _http = it.next();
    it.next().and_then(|s| s.parse::<u16>().ok()).unwrap_or(0)
}

fn split_body(resp: &str) -> String {
    match resp.find("\r\n\r\n") {
        Some(i) => resp[i + 4..].to_string(),
        None => String::new(),
    }
}

impl TlsOutcome {
    /// 结果回给 Kotlin（body 原样带回：trace 文本就是判据本身）
    pub fn to_json(&self) -> String {
        format!(
            "{{\"ok\":{},\"hs_ms\":{},\"established\":{},\"tls_version\":\"{}\",\"alpn\":\"{}\",\"ech_override\":{},\"ech_retry_len\":{},\"status\":{},\"total_ms\":{},\"body_len\":{},\"body\":\"{}\",\"error\":{}}}",
            self.error.is_none(),
            self.hs_ms,
            self.established,
            json_escape(&self.tls_version),
            json_escape(&self.alpn),
            match &self.ech_override {
                Some(n) => format!("\"{}\"", json_escape(n)),
                None => "null".to_string(),
            },
            self.ech_retry_len,
            self.status,
            self.total_ms,
            self.body_len,
            json_escape(&self.body),
            match &self.error {
                Some(e) => format!("\"{}\"", json_escape(e)),
                None => "null".to_string(),
            }
        )
    }
}

fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}
