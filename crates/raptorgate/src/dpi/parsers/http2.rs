use std::collections::VecDeque;

use super::http2_huffman::HUFFMAN_CODES;

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_HEADER_LEN: usize = 9;
const TYPE_DATA: u8 = 0x0;
const TYPE_HEADERS: u8 = 0x1;
const TYPE_SETTINGS: u8 = 0x4;
const TYPE_PING: u8 = 0x6;
const TYPE_WINDOW_UPDATE: u8 = 0x8;
const TYPE_CONTINUATION: u8 = 0x9;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;
const MAX_FRAMES: usize = 64;

const STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Http2ParseResult {
    pub method: Option<String>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub normalized_payload: Option<Vec<u8>>,
}

struct HeaderBlock {
    stream_id: u32,
    fragments: Vec<u8>,
}

struct SelectedStream {
    stream_id: u32,
    result: Http2ParseResult,
}

pub fn parse_http2(buf: &[u8]) -> Option<Http2ParseResult> {
    let mut offset = 0usize;
    let mut saw_http2 = false;
    if buf.starts_with(CLIENT_PREFACE) {
        offset = CLIENT_PREFACE.len();
        saw_http2 = true;
    }

    let mut decoder = HpackDecoder::new(4096);
    let mut pending: Option<HeaderBlock> = None;
    let mut selected: Option<SelectedStream> = None;
    let mut frames = 0usize;

    while offset + FRAME_HEADER_LEN <= buf.len() && frames < MAX_FRAMES {
        let length = ((usize::from(buf[offset])) << 16)
            | ((usize::from(buf[offset + 1])) << 8)
            | usize::from(buf[offset + 2]);
        let frame_type = buf[offset + 3];
        let flags = buf[offset + 4];
        let stream_id = u32::from_be_bytes([
            buf[offset + 5] & 0x7f,
            buf[offset + 6],
            buf[offset + 7],
            buf[offset + 8],
        ]);
        let frame_end = offset + FRAME_HEADER_LEN + length;
        if frame_end > buf.len() {
            break;
        }

        if is_plausible_frame(frame_type, stream_id, frames) {
            saw_http2 = true;
        } else if !saw_http2 {
            return None;
        }

        let payload = &buf[offset + FRAME_HEADER_LEN..frame_end];
        match frame_type {
            TYPE_HEADERS => {
                let fragment = headers_fragment(payload, flags)?;
                pending = Some(HeaderBlock {
                    stream_id,
                    fragments: fragment.to_vec(),
                });
                if flags & FLAG_END_HEADERS != 0 {
                    complete_header_block(&mut decoder, pending.take(), &mut selected);
                }
            }
            TYPE_CONTINUATION => {
                if let Some(current) = pending.as_mut() {
                    if current.stream_id == stream_id {
                        current.fragments.extend_from_slice(payload);
                        if flags & FLAG_END_HEADERS != 0 {
                            complete_header_block(&mut decoder, pending.take(), &mut selected);
                        }
                    } else {
                        pending = None;
                    }
                }
            }
            TYPE_DATA => {
                if let Some(current) = selected.as_mut() {
                    if current.stream_id == stream_id {
                        let data = data_payload(payload, flags)?;
                        if !data.is_empty() {
                            if let Some(normalized) = current.result.normalized_payload.as_mut() {
                                normalized.extend_from_slice(data);
                            } else {
                                current.result.normalized_payload = Some(data.to_vec());
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        offset = frame_end;
        frames += 1;
    }

    selected.map(|stream| stream.result).or_else(|| saw_http2.then_some(Http2ParseResult::default()))
}

fn is_plausible_frame(frame_type: u8, stream_id: u32, frames: usize) -> bool {
    match frame_type {
        TYPE_HEADERS | TYPE_DATA | TYPE_CONTINUATION => stream_id != 0,
        TYPE_SETTINGS | TYPE_PING | TYPE_WINDOW_UPDATE => frames > 0 || stream_id == 0,
        _ => frames > 0,
    }
}

fn headers_fragment(payload: &[u8], flags: u8) -> Option<&[u8]> {
    let mut start = 0usize;
    let mut end = payload.len();
    if flags & FLAG_PADDED != 0 {
        let pad_len = usize::from(*payload.first()?);
        start += 1;
        if start + pad_len > end {
            return None;
        }
        end -= pad_len;
    }
    if flags & FLAG_PRIORITY != 0 {
        if start + 5 > end {
            return None;
        }
        start += 5;
    }
    payload.get(start..end)
}

fn data_payload(payload: &[u8], flags: u8) -> Option<&[u8]> {
    if flags & FLAG_PADDED == 0 {
        return Some(payload);
    }
    let pad_len = usize::from(*payload.first()?);
    let start = 1usize;
    let end = payload.len().checked_sub(pad_len)?;
    payload.get(start..end)
}

fn complete_header_block(
    decoder: &mut HpackDecoder,
    block: Option<HeaderBlock>,
    selected: &mut Option<SelectedStream>,
) {
    let Some(block) = block else {
        return;
    };
    let Some(headers) = decoder.decode_block(&block.fragments) else {
        return;
    };
    let result = build_result(&headers);
    if selected.is_none() {
        *selected = Some(SelectedStream {
            stream_id: block.stream_id,
            result,
        });
    }
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

struct HpackDecoder {
    dynamic_table: VecDeque<(String, String)>,
    dynamic_size: usize,
    max_dynamic_size: usize,
}

impl HpackDecoder {
    fn new(max_dynamic_size: usize) -> Self {
        Self {
            dynamic_table: VecDeque::new(),
            dynamic_size: 0,
            max_dynamic_size,
        }
    }

    fn decode_block(&mut self, block: &[u8]) -> Option<Vec<(String, String)>> {
        let mut pos = 0usize;
        let mut headers = Vec::new();
        while pos < block.len() {
            let byte = *block.get(pos)?;
            if byte & 0x80 != 0 {
                let (index, next) = decode_int(block, pos, 7)?;
                pos = next;
                headers.push(self.header_at(index)?);
            } else if byte & 0x40 != 0 {
                let (header, next) = self.decode_literal(block, pos, 6)?;
                self.insert(header.clone());
                headers.push(header);
                pos = next;
            } else if byte & 0x20 != 0 {
                let (new_size, next) = decode_int(block, pos, 5)?;
                self.set_max_dynamic_size(new_size);
                pos = next;
            } else {
                let (header, next) = self.decode_literal(block, pos, 4)?;
                headers.push(header);
                pos = next;
            }
        }
        Some(headers)
    }

    fn decode_literal(
        &mut self,
        block: &[u8],
        pos: usize,
        prefix: u8,
    ) -> Option<((String, String), usize)> {
        let (name_index, mut pos) = decode_int(block, pos, prefix)?;
        let name = if name_index == 0 {
            let (name, next) = decode_string(block, pos)?;
            pos = next;
            name
        } else {
            self.header_at(name_index)?.0
        };
        let (value, pos) = decode_string(block, pos)?;
        Some(((name, value), pos))
    }

    fn header_at(&self, index: usize) -> Option<(String, String)> {
        if index == 0 {
            return None;
        }
        if index <= STATIC_TABLE.len() {
            let (name, value) = STATIC_TABLE[index - 1];
            return Some((name.to_owned(), value.to_owned()));
        }
        let dynamic_index = index.checked_sub(STATIC_TABLE.len() + 1)?;
        self.dynamic_table.get(dynamic_index).cloned()
    }

    fn insert(&mut self, header: (String, String)) {
        let entry_size = header.0.len() + header.1.len() + 32;
        if entry_size > self.max_dynamic_size {
            self.dynamic_table.clear();
            self.dynamic_size = 0;
            return;
        }
        self.dynamic_size += entry_size;
        self.dynamic_table.push_front(header);
        self.evict();
    }

    fn set_max_dynamic_size(&mut self, new_size: usize) {
        self.max_dynamic_size = new_size;
        self.evict();
    }

    fn evict(&mut self) {
        while self.dynamic_size > self.max_dynamic_size {
            let Some((name, value)) = self.dynamic_table.pop_back() else {
                self.dynamic_size = 0;
                break;
            };
            self.dynamic_size = self.dynamic_size.saturating_sub(name.len() + value.len() + 32);
        }
    }
}

fn decode_int(block: &[u8], pos: usize, prefix: u8) -> Option<(usize, usize)> {
    if !(1..=8).contains(&prefix) {
        return None;
    }
    let first = *block.get(pos)?;
    let mask = if prefix == 8 {
        0xff
    } else {
        (1u8 << prefix) - 1
    };
    let mut value = usize::from(first & mask);
    let mut next = pos + 1;
    if value < usize::from(mask) {
        return Some((value, next));
    }

    let mut shift = 0usize;
    loop {
        let byte = *block.get(next)?;
        next += 1;
        value = value.checked_add(usize::from(byte & 0x7f) << shift)?;
        if byte & 0x80 == 0 {
            return Some((value, next));
        }
        shift += 7;
        if shift > 28 {
            return None;
        }
    }
}

fn decode_string(block: &[u8], pos: usize) -> Option<(String, usize)> {
    let first = *block.get(pos)?;
    let huffman = first & 0x80 != 0;
    let (len, start) = decode_int(block, pos, 7)?;
    let end = start.checked_add(len)?;
    let slice = block.get(start..end)?;
    let value = if huffman {
        decode_huffman(slice)?
    } else {
        String::from_utf8_lossy(slice).into_owned()
    };
    Some((value, end))
}

fn decode_huffman(src: &[u8]) -> Option<String> {
    let mut out = Vec::with_capacity(src.len().saturating_mul(2));
    let mut bits = 0u64;
    let mut bit_len = 0usize;

    for &byte in src {
        bits = (bits << 8) | u64::from(byte);
        bit_len += 8;

        loop {
            let Some((symbol, len)) = match_symbol(bits, bit_len) else {
                break;
            };
            if symbol == 256 {
                return None;
            }
            out.push(symbol as u8);
            bit_len -= usize::from(len);
            if bit_len == 0 {
                bits = 0;
            } else {
                bits &= (1u64 << bit_len) - 1;
            }
        }

        if bit_len > 32 {
            return None;
        }
    }

    if bit_len > 7 {
        return None;
    }
    if bit_len > 0 && bits != (1u64 << bit_len) - 1 {
        return None;
    }

    Some(String::from_utf8_lossy(&out).into_owned())
}

fn match_symbol(bits: u64, bit_len: usize) -> Option<(usize, u8)> {
    for (symbol, (code, len)) in HUFFMAN_CODES.iter().enumerate() {
        if symbol == 256 {
            continue;
        }
        let len_usize = usize::from(*len);
        if len_usize > bit_len {
            continue;
        }
        let mask = if len_usize == 64 {
            u64::MAX
        } else {
            (1u64 << len_usize) - 1
        };
        let candidate = ((bits >> (bit_len - len_usize)) & mask) as u32;
        if candidate == *code {
            return Some((symbol, *len));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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
