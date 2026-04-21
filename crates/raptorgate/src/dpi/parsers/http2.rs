use h2_sans_io::{CONNECTION_PREFACE as CLIENT_PREFACE, H2Codec, H2Event, H2Header, HpackDecoder};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Http2ParseResult {
    pub method: Option<String>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub normalized_payload: Option<Vec<u8>>,
}

struct SelectedStream {
    stream_id: u32,
    result: Http2ParseResult,
}

pub fn parse_http2(buf: &[u8]) -> Option<Http2ParseResult> {
    let mut codec = H2Codec::new();
    let saw_preface = buf.starts_with(CLIENT_PREFACE);
    let events = match codec.process(buf) {
        Ok(events) => events,
        Err(_) => return saw_preface.then_some(Http2ParseResult::default()),
    };

    let mut saw_http2 = saw_preface || !events.is_empty();
    let mut decoder = HpackDecoder::new();
    let mut selected: Option<SelectedStream> = None;

    for event in events {
        match event {
            H2Event::Headers {
                stream_id,
                header_block,
                ..
            } => {
                saw_http2 = true;
                if selected.is_none() {
                    let Some(headers) = decode_header_block(&mut decoder, &header_block) else {
                        continue;
                    };
                    selected = Some(SelectedStream {
                        stream_id,
                        result: build_result(&headers),
                    });
                } else {
                    let _ = decoder.decode(&header_block);
                }
            }
            H2Event::Data { stream_id, data, .. } => {
                saw_http2 = true;
                if let Some(current) = selected.as_mut() {
                    if current.stream_id == stream_id && !data.is_empty() {
                        if let Some(normalized) = current.result.normalized_payload.as_mut() {
                            normalized.extend_from_slice(&data);
                        } else {
                            current.result.normalized_payload = Some(data);
                        }
                    }
                }
            }
            _ => {
                saw_http2 = true;
            }
        }
    }

    selected.map(|stream| stream.result).or_else(|| saw_http2.then_some(Http2ParseResult::default()))
}

fn decode_header_block(
    decoder: &mut HpackDecoder,
    header_block: &[u8],
) -> Option<Vec<(String, String)>> {
    let headers = decoder.decode(header_block).ok()?;
    let mut out = Vec::with_capacity(headers.len());
    for header in headers {
        out.push(header_to_pair(header)?);
    }
    Some(out)
}

fn header_to_pair(header: H2Header) -> Option<(String, String)> {
    let name = std::str::from_utf8(&header.name).ok()?.to_owned();
    let value = String::from_utf8_lossy(&header.value).into_owned();
    Some((name, value))
}

fn build_result(headers: &[(String, String)]) -> Http2ParseResult {
    let mut method = None;
    let mut path = None;
    let mut status = None;
    let mut authority = None;
    let mut host = None;
    let mut user_agent = None;
    let mut content_type = None;
    let mut regular_headers = Vec::new();

    for (name, value) in headers {
        match name.as_str() {
            ":method" => method = Some(value.clone()),
            ":path" => path = Some(value.clone()),
            ":status" => status = Some(value.clone()),
            ":authority" => authority = Some(value.clone()),
            "host" => host = Some(value.clone()),
            "user-agent" => user_agent = Some(value.clone()),
            "content-type" => content_type = Some(value.clone()),
            _ => {}
        }
        if !name.starts_with(':') {
            regular_headers.push((name.clone(), value.clone()));
        }
    }

    let host = authority.or(host);
    let normalized_payload = build_normalized_payload(
        method.as_deref(),
        path.as_deref(),
        status.as_deref(),
        host.as_deref(),
        &regular_headers,
    );

    Http2ParseResult {
        method,
        host,
        user_agent,
        content_type,
        normalized_payload,
    }
}

fn build_normalized_payload(
    method: Option<&str>,
    path: Option<&str>,
    status: Option<&str>,
    host: Option<&str>,
    headers: &[(String, String)],
) -> Option<Vec<u8>> {
    if method.is_none() && status.is_none() && headers.is_empty() {
        return None;
    }

    let mut payload = Vec::new();
    if let Some(method) = method {
        payload.extend_from_slice(method.as_bytes());
        payload.extend_from_slice(b" ");
        payload.extend_from_slice(path.unwrap_or("/").as_bytes());
        payload.extend_from_slice(b" HTTP/2\r\n");
    } else if let Some(status) = status {
        payload.extend_from_slice(b"HTTP/2 ");
        payload.extend_from_slice(status.as_bytes());
        payload.extend_from_slice(b"\r\n");
    } else {
        payload.extend_from_slice(b"HTTP/2\r\n");
    }

    if let Some(host) = host {
        payload.extend_from_slice(b"Host: ");
        payload.extend_from_slice(host.as_bytes());
        payload.extend_from_slice(b"\r\n");
    }

    for (name, value) in headers {
        if name == "host" {
            continue;
        }
        payload.extend_from_slice(name.as_bytes());
        payload.extend_from_slice(b": ");
        payload.extend_from_slice(value.as_bytes());
        payload.extend_from_slice(b"\r\n");
    }

    payload.extend_from_slice(b"\r\n");
    Some(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TYPE_DATA: u8 = 0x0;
    const TYPE_HEADERS: u8 = 0x1;
    const TYPE_SETTINGS: u8 = 0x4;
    const FLAG_END_HEADERS: u8 = 0x4;

    fn encode_int(mut value: usize, prefix: u8, lead: u8) -> Vec<u8> {
        let max_prefix = (1usize << prefix) - 1;
        if value < max_prefix {
            return vec![lead | value as u8];
        }

        let mut out = vec![lead | max_prefix as u8];
        value -= max_prefix;
        while value >= 128 {
            out.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
        out
    }

    fn encode_string(value: &str) -> Vec<u8> {
        let mut out = encode_int(value.len(), 7, 0);
        out.extend_from_slice(value.as_bytes());
        out
    }

    fn indexed(index: usize) -> Vec<u8> {
        encode_int(index, 7, 0x80)
    }

    fn literal_with_indexed_name(index: usize, value: &str) -> Vec<u8> {
        let mut out = encode_int(index, 4, 0);
        out.extend_from_slice(&encode_string(value));
        out
    }

    fn frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut out = vec![
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
            frame_type,
            flags,
            ((stream_id >> 24) & 0x7f) as u8,
            ((stream_id >> 16) & 0xff) as u8,
            ((stream_id >> 8) & 0xff) as u8,
            (stream_id & 0xff) as u8,
        ];
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn parses_client_preface_and_request_headers() {
        let mut block = Vec::new();
        block.extend_from_slice(&indexed(2));
        block.extend_from_slice(&indexed(7));
        block.extend_from_slice(&indexed(4));
        block.extend_from_slice(&literal_with_indexed_name(1, "example.com"));
        block.extend_from_slice(&literal_with_indexed_name(58, "curl/8.0"));

        let mut payload = CLIENT_PREFACE.to_vec();
        payload.extend_from_slice(&frame(TYPE_SETTINGS, 0, 0, &[]));
        payload.extend_from_slice(&frame(TYPE_HEADERS, FLAG_END_HEADERS, 1, &block));

        let result = parse_http2(&payload).unwrap();
        assert_eq!(result.method.as_deref(), Some("GET"));
        assert_eq!(result.host.as_deref(), Some("example.com"));
        assert_eq!(result.user_agent.as_deref(), Some("curl/8.0"));
        let normalized = String::from_utf8(result.normalized_payload.unwrap()).unwrap();
        assert!(normalized.starts_with("GET / HTTP/2\r\n"));
        assert!(normalized.contains("Host: example.com\r\n"));
        assert!(normalized.contains("user-agent: curl/8.0\r\n"));
    }

    #[test]
    fn parses_response_headers_without_preface() {
        let mut block = Vec::new();
        block.extend_from_slice(&indexed(8));
        block.extend_from_slice(&literal_with_indexed_name(31, "text/html"));
        let payload = frame(TYPE_HEADERS, FLAG_END_HEADERS, 1, &block);

        let result = parse_http2(&payload).unwrap();
        assert_eq!(result.method, None);
        assert_eq!(result.content_type.as_deref(), Some("text/html"));
        let normalized = String::from_utf8(result.normalized_payload.unwrap()).unwrap();
        assert!(normalized.starts_with("HTTP/2 200\r\n"));
        assert!(normalized.contains("content-type: text/html\r\n"));
    }

    #[test]
    fn appends_data_for_selected_stream() {
        let mut block = Vec::new();
        block.extend_from_slice(&indexed(2));
        block.extend_from_slice(&indexed(7));
        block.extend_from_slice(&indexed(4));
        block.extend_from_slice(&literal_with_indexed_name(1, "example.com"));

        let mut payload = CLIENT_PREFACE.to_vec();
        payload.extend_from_slice(&frame(TYPE_SETTINGS, 0, 0, &[]));
        payload.extend_from_slice(&frame(TYPE_HEADERS, FLAG_END_HEADERS, 1, &block));
        payload.extend_from_slice(&frame(TYPE_DATA, 0, 1, b"body"));

        let result = parse_http2(&payload).unwrap();
        let normalized = String::from_utf8(result.normalized_payload.unwrap()).unwrap();
        assert!(normalized.ends_with("\r\n\r\nbody"));
    }
}
