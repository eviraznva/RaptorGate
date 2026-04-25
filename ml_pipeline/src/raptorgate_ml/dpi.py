from dataclasses import dataclass, field


@dataclass
class DpiContext:
    app_proto: int | None = None
    tls_sni: str | None = None
    tls_ech_detected: bool = False
    tls_version: int | None = None
    tls_alpn: list[str] = field(default_factory=list)
    http_method: str | None = None
    http_host: str | None = None
    http_user_agent: str | None = None
    http_normalized_payload: bytes | None = None
    dns_query_name: str | None = None
    dns_query_type_code: int | None = None
    dns_answer_count: int = 0
    dns_rcode: int = 0


_APP_TLS, _APP_HTTP, _APP_DNS, _APP_SSH, _APP_QUIC = 1, 2, 3, 4, 5
_APP_SMTP, _APP_FTP, _APP_RDP, _APP_SMB = 6, 7, 8, 9

_PORT_HINTS = {
    443: _APP_TLS,
    8443: _APP_TLS,
    80: _APP_HTTP,
    8080: _APP_HTTP,
    53: _APP_DNS,
    22: _APP_SSH,
    25: _APP_SMTP,
    587: _APP_SMTP,
    21: _APP_FTP,
    3389: _APP_RDP,
    445: _APP_SMB,
}

_TLS_EXT_SNI = 0x0000
_TLS_EXT_ALPN = 0x0010
_TLS_EXT_ECH = 0xFE0D


def inspect(payload: bytes, src_port: int, dst_port: int, udp: bool) -> DpiContext:
    ctx = DpiContext()
    ctx.app_proto = _PORT_HINTS.get(dst_port) or _PORT_HINTS.get(src_port)

    if not payload:
        return ctx

    if ctx.app_proto == _APP_TLS or _looks_like_tls(payload):
        ctx.app_proto = _APP_TLS
        _parse_tls_client_hello(payload, ctx)
    elif ctx.app_proto == _APP_HTTP or _looks_like_http(payload):
        ctx.app_proto = _APP_HTTP
        _parse_http(payload, ctx)
    elif ctx.app_proto == _APP_DNS or (udp and (src_port == 53 or dst_port == 53)):
        ctx.app_proto = _APP_DNS
        _parse_dns(payload, ctx)

    return ctx


def _looks_like_tls(p: bytes) -> bool:
    return len(p) >= 6 and p[0] in (0x16, 0x17, 0x14, 0x15) and p[1] == 0x03


def _looks_like_http(p: bytes) -> bool:
    head = p[:16]
    return (
        head.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"OPTIONS", b"DELETE "))
        or head.startswith(b"CONNECT ")
        or head.startswith(b"HTTP/1.")
    )


def _parse_tls_client_hello(p: bytes, ctx: DpiContext) -> None:
    if len(p) < 43 or p[0] != 0x16:
        return
    rec_version = int.from_bytes(p[1:3], "big")
    hs_type = p[5]
    if hs_type != 0x01:
        return
    ctx.tls_version = rec_version
    i = 5 + 4 + 2 + 32
    if i >= len(p):
        return
    sid_len = p[i]
    i += 1 + sid_len
    if i + 2 > len(p):
        return
    cs_len = int.from_bytes(p[i : i + 2], "big")
    i += 2 + cs_len
    if i + 1 > len(p):
        return
    comp_len = p[i]
    i += 1 + comp_len
    if i + 2 > len(p):
        return
    ext_total = int.from_bytes(p[i : i + 2], "big")
    i += 2
    end = min(len(p), i + ext_total)
    while i + 4 <= end:
        ext_type = int.from_bytes(p[i : i + 2], "big")
        ext_len = int.from_bytes(p[i + 2 : i + 4], "big")
        ext_body = p[i + 4 : i + 4 + ext_len]
        i += 4 + ext_len
        if ext_type == _TLS_EXT_SNI:
            ctx.tls_sni = _extract_sni(ext_body)
        elif ext_type == _TLS_EXT_ALPN:
            ctx.tls_alpn = _extract_alpn(ext_body)
        elif ext_type == _TLS_EXT_ECH:
            ctx.tls_ech_detected = True
        elif ext_type == 0x002B and ext_len >= 3:
            for j in range(1, ext_len - 1, 2):
                v = int.from_bytes(ext_body[j : j + 2], "big")
                if v == 0x0304:
                    ctx.tls_version = 0x0304
                    break


def _extract_sni(body: bytes) -> str | None:
    if len(body) < 5:
        return None
    j = 2
    name_type = body[j]
    j += 1
    name_len = int.from_bytes(body[j : j + 2], "big")
    j += 2
    if name_type != 0x00 or j + name_len > len(body):
        return None
    try:
        return body[j : j + name_len].decode("ascii")
    except UnicodeDecodeError:
        return None


def _extract_alpn(body: bytes) -> list[str]:
    if len(body) < 2:
        return []
    list_len = int.from_bytes(body[:2], "big")
    out: list[str] = []
    j = 2
    end = min(len(body), 2 + list_len)
    while j < end:
        ln = body[j]
        j += 1
        if j + ln > end:
            break
        try:
            out.append(body[j : j + ln].decode("ascii"))
        except UnicodeDecodeError:
            pass
        j += ln
    return out


def _parse_http(p: bytes, ctx: DpiContext) -> None:
    try:
        head, _, body = p.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        if not lines:
            return
        first = lines[0].decode("latin-1", errors="ignore")
        parts = first.split(" ")
        if len(parts) >= 1 and not first.startswith("HTTP/"):
            ctx.http_method = parts[0]
        for line in lines[1:]:
            if b":" not in line:
                continue
            name, _, value = line.partition(b":")
            key = name.strip().lower().decode("latin-1", errors="ignore")
            val = value.strip().decode("latin-1", errors="ignore")
            if key == "host":
                ctx.http_host = val
            elif key == "user-agent":
                ctx.http_user_agent = val
        if body:
            ctx.http_normalized_payload = body
    except Exception:
        return


def _parse_dns(p: bytes, ctx: DpiContext) -> None:
    if len(p) < 12:
        return
    flags = int.from_bytes(p[2:4], "big")
    qd = int.from_bytes(p[4:6], "big")
    an = int.from_bytes(p[6:8], "big")
    ctx.dns_answer_count = an
    ctx.dns_rcode = flags & 0x000F
    if qd == 0:
        return
    i = 12
    labels: list[str] = []
    while i < len(p):
        ln = p[i]
        i += 1
        if ln == 0:
            break
        if ln & 0xC0:
            i += 1
            break
        if i + ln > len(p):
            return
        labels.append(p[i : i + ln].decode("ascii", errors="ignore"))
        i += ln
    if labels:
        ctx.dns_query_name = ".".join(labels)
    if i + 2 <= len(p):
        ctx.dns_query_type_code = int.from_bytes(p[i : i + 2], "big")
