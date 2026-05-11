from enum import IntEnum


class MlL4Proto(IntEnum):
    Other = 0
    Tcp = 1
    Udp = 2
    Icmp = 3
    Sctp = 4

    @classmethod
    def from_ip_proto(cls, n: int) -> "MlL4Proto":
        if n == 6:
            return cls.Tcp
        if n == 17:
            return cls.Udp
        if n in (1, 58):
            return cls.Icmp
        if n == 132:
            return cls.Sctp
        return cls.Other


class MlAppProto(IntEnum):
    Unknown = 0
    Tls = 1
    Http = 2
    Dns = 3
    Ssh = 4
    Quic = 5
    Smtp = 6
    Ftp = 7
    Rdp = 8
    Smb = 9
    Other = 10


class MlTlsVersion(IntEnum):
    Unknown = 0
    Ssl3 = 1
    Tls10 = 2
    Tls11 = 3
    Tls12 = 4
    Tls13 = 5

    @classmethod
    def from_raw(cls, v: int) -> "MlTlsVersion":
        return {
            0x0300: cls.Ssl3,
            0x0301: cls.Tls10,
            0x0302: cls.Tls11,
            0x0303: cls.Tls12,
            0x0304: cls.Tls13,
        }.get(v, cls.Unknown)


class MlHttpMethod(IntEnum):
    Null = 0
    Get = 1
    Post = 2
    Put = 3
    Delete = 4
    Head = 5
    Options = 6
    Connect = 7
    Other = 8

    @classmethod
    def from_str_case_insensitive(cls, s: str) -> "MlHttpMethod":
        return {
            "GET": cls.Get,
            "POST": cls.Post,
            "PUT": cls.Put,
            "DELETE": cls.Delete,
            "HEAD": cls.Head,
            "OPTIONS": cls.Options,
            "CONNECT": cls.Connect,
        }.get(s.upper(), cls.Other)


class MlQtype(IntEnum):
    Null = 0
    A = 1
    Aaaa = 2
    Cname = 3
    Mx = 4
    Txt = 5
    Ns = 6
    Ptr = 7
    Srv = 8
    Soa = 9
    Https = 10
    Svcb = 11
    Any = 12
    Axfr = 13
    Other = 14

    @classmethod
    def from_dns_type_code(cls, code: int) -> "MlQtype":
        return {
            1: cls.A,
            28: cls.Aaaa,
            5: cls.Cname,
            15: cls.Mx,
            16: cls.Txt,
            2: cls.Ns,
            12: cls.Ptr,
            33: cls.Srv,
            6: cls.Soa,
            65: cls.Https,
            64: cls.Svcb,
            255: cls.Any,
            252: cls.Axfr,
        }.get(code, cls.Other)


class MlPortClass(IntEnum):
    Unknown = 0
    WellKnown = 1
    Registered = 2
    Dynamic = 3

    @classmethod
    def from_port(cls, port: int) -> "MlPortClass":
        if port == 0:
            return cls.Unknown
        if 1 <= port <= 1023:
            return cls.WellKnown
        if 1024 <= port <= 49151:
            return cls.Registered
        return cls.Dynamic
