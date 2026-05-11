use httparse::{Header, Request, Response, Status, EMPTY_HEADER};

use crate::dpi::context::DpiContext;
use crate::dpi::AppProto;

const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const MAX_HEADERS: usize = 32;

// Wynik parsowania HTTP: metoda, nagłówki i wersja protokołu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpParseResult {
    pub is_http2: bool,
    pub method: Option<String>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
}

// Parsuje payload HTTP/1.1 (request/response) lub rozpoznaje HTTP/2 preface.
// TODO: Po wdrożeniu inspekcji ssl/tls (proxy mitm) dodać dekompresję HPACK
// dla HTTP/2 parsowanie ramek HEADERS (type 0x01) i ekstrakcja :authority, :method.
pub fn parse_http(buf: &[u8]) -> Option<HttpParseResult> {
    if buf.len() >= HTTP2_PREFACE.len() && buf.starts_with(HTTP2_PREFACE) {
        return Some(HttpParseResult {
            is_http2: true,
            method: None,
            host: None,
            user_agent: None,
            content_type: None,
        });
    }

    if let Some(result) = try_parse_request(buf) {
        return Some(result);
    }

    try_parse_response(buf)
}

fn try_parse_request(buf: &[u8]) -> Option<HttpParseResult> {
    let mut headers = [EMPTY_HEADER; MAX_HEADERS];
    let mut req = Request::new(&mut headers);

    match req.parse(buf) {
        Ok(Status::Complete(_)) | Ok(Status::Partial) => {}
        Err(_) => return None,
    }

    req.method?;

    let method = req.method.map(|m| m.to_owned());
    let host = find_header(req.headers, "host");
    let user_agent = find_header(req.headers, "user-agent");
    let content_type = find_header(req.headers, "content-type");

    Some(HttpParseResult {
        is_http2: false,
        method,
        host,
        user_agent,
        content_type,
    })
}

fn try_parse_response(buf: &[u8]) -> Option<HttpParseResult> {
    let mut headers = [EMPTY_HEADER; MAX_HEADERS];
    let mut resp = Response::new(&mut headers);

    match resp.parse(buf) {
        Ok(Status::Complete(_)) | Ok(Status::Partial) => {}
        Err(_) => return None,
    }

    resp.version?;

    let content_type = find_header(resp.headers, "content-type");

    Some(HttpParseResult {
        is_http2: false,
        method: None,
        host: None,
        user_agent: None,
        content_type,
    })
}

fn find_header(headers: &[Header], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .map(|v| v.to_owned())
}

// Konwertuje wynik parsowania HTTP na DpiContext.
pub fn http_to_dpi_context(result: &HttpParseResult) -> DpiContext {
    DpiContext {
        app_proto: Some(AppProto::Http),
        http_host: result.host.clone(),
        http_method: result.method.clone(),
        http_user_agent: result.user_agent.clone(),
        http_content_type: result.content_type.clone(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_request_basic() {
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = parse_http(buf).unwrap();
        assert!(!result.is_http2);
        assert_eq!(result.method.as_deref(), Some("GET"));
        assert_eq!(result.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn post_with_headers() {
        let buf = b"POST /api HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nUser-Agent: test/1.0\r\n\r\n";
        let result = parse_http(buf).unwrap();
        assert_eq!(result.method.as_deref(), Some("POST"));
        assert_eq!(result.host.as_deref(), Some("api.example.com"));
        assert_eq!(result.content_type.as_deref(), Some("application/json"));
        assert_eq!(result.user_agent.as_deref(), Some("test/1.0"));
    }

    #[test]
    fn partial_request_with_method() {
        let buf = b"GET /path HTTP/1.1\r\nHost: partial.com\r\n";
        let result = parse_http(buf).unwrap();
        assert_eq!(result.method.as_deref(), Some("GET"));
        assert_eq!(result.host.as_deref(), Some("partial.com"));
    }

    #[test]
    fn response_with_content_type() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        let result = parse_http(buf).unwrap();
        assert!(!result.is_http2);
        assert_eq!(result.method, None);
        assert_eq!(result.content_type.as_deref(), Some("text/html"));
    }

    #[test]
    fn http2_preface() {
        let result = parse_http(HTTP2_PREFACE).unwrap();
        assert!(result.is_http2);
        assert_eq!(result.method, None);
        assert_eq!(result.host, None);
    }

    #[test]
    fn http2_preface_with_trailing_data() {
        let mut buf = HTTP2_PREFACE.to_vec();
        buf.extend_from_slice(&[0x00, 0x00, 0x12, 0x04, 0x00]);
        let result = parse_http(&buf).unwrap();
        assert!(result.is_http2);
    }

    #[test]
    fn head_request() {
        let buf = b"HEAD /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = parse_http(buf).unwrap();
        assert_eq!(result.method.as_deref(), Some("HEAD"));
    }

    #[test]
    fn put_request() {
        let buf = b"PUT /resource HTTP/1.1\r\nHost: api.com\r\n\r\n";
        let result = parse_http(buf).unwrap();
        assert_eq!(result.method.as_deref(), Some("PUT"));
    }

    #[test]
    fn delete_request() {
        let buf = b"DELETE /item/42 HTTP/1.1\r\nHost: api.com\r\n\r\n";
        let result = parse_http(buf).unwrap();
        assert_eq!(result.method.as_deref(), Some("DELETE"));
    }

    #[test]
    fn options_request() {
        let buf = b"OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = parse_http(buf).unwrap();
        assert_eq!(result.method.as_deref(), Some("OPTIONS"));
    }

    #[test]
    fn connect_request() {
        let buf = b"CONNECT proxy.example.com:443 HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n";
        let result = parse_http(buf).unwrap();
        assert_eq!(result.method.as_deref(), Some("CONNECT"));
        assert_eq!(result.host.as_deref(), Some("proxy.example.com"));
    }

    #[test]
    fn header_case_insensitive() {
        let buf = b"GET / HTTP/1.1\r\nhOsT: Case.Example.COM\r\nuser-AGENT: Bot/2\r\n\r\n";
        let result = parse_http(buf).unwrap();
        assert_eq!(result.host.as_deref(), Some("Case.Example.COM"));
        assert_eq!(result.user_agent.as_deref(), Some("Bot/2"));
    }

    #[test]
    fn no_host_header() {
        let buf = b"GET / HTTP/1.0\r\n\r\n";
        let result = parse_http(buf).unwrap();
        assert_eq!(result.method.as_deref(), Some("GET"));
        assert_eq!(result.host, None);
    }

    #[test]
    fn response_partial() {
        let buf = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n";
        let result = parse_http(buf).unwrap();
        assert_eq!(result.content_type.as_deref(), Some("text/plain"));
    }

    #[test]
    fn binary_garbage() {
        let buf = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
        assert!(parse_http(&buf).is_none());
    }

    #[test]
    fn empty_input() {
        assert!(parse_http(&[]).is_none());
    }

    #[test]
    fn too_short() {
        assert!(parse_http(b"GE").is_none());
    }

    #[test]
    fn to_dpi_context_full() {
        let result = HttpParseResult {
            is_http2: false,
            method: Some("POST".into()),
            host: Some("example.com".into()),
            user_agent: Some("curl/8.0".into()),
            content_type: Some("application/json".into()),
        };
        let ctx = http_to_dpi_context(&result);
        assert_eq!(ctx.app_proto, Some(AppProto::Http));
        assert_eq!(ctx.http_method.as_deref(), Some("POST"));
        assert_eq!(ctx.http_host.as_deref(), Some("example.com"));
        assert_eq!(ctx.http_user_agent.as_deref(), Some("curl/8.0"));
        assert_eq!(ctx.http_content_type.as_deref(), Some("application/json"));
    }

    #[test]
    fn to_dpi_context_http2() {
        let result = HttpParseResult {
            is_http2: true,
            method: None,
            host: None,
            user_agent: None,
            content_type: None,
        };
        let ctx = http_to_dpi_context(&result);
        assert_eq!(ctx.app_proto, Some(AppProto::Http));
        assert_eq!(ctx.http_host, None);
    }

    #[test]
    fn to_dpi_context_no_optional_headers() {
        let result = HttpParseResult {
            is_http2: false,
            method: Some("GET".into()),
            host: None,
            user_agent: None,
            content_type: None,
        };
        let ctx = http_to_dpi_context(&result);
        assert_eq!(ctx.app_proto, Some(AppProto::Http));
        assert_eq!(ctx.http_method.as_deref(), Some("GET"));
        assert_eq!(ctx.http_host, None);
        assert_eq!(ctx.http_user_agent, None);
    }
}
