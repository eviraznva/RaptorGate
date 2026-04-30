from raptorgate_ml.enums import (
    MlAppProto,
    MlHttpMethod,
    MlL4Proto,
    MlPortClass,
    MlQtype,
    MlTlsVersion,
)


def test_l4_proto_values_match_rust():
    assert MlL4Proto.Other.value == 0
    assert MlL4Proto.Tcp.value == 1
    assert MlL4Proto.Udp.value == 2
    assert MlL4Proto.Icmp.value == 3
    assert MlL4Proto.Sctp.value == 4


def test_l4_from_ip_proto():
    assert MlL4Proto.from_ip_proto(6) == MlL4Proto.Tcp
    assert MlL4Proto.from_ip_proto(17) == MlL4Proto.Udp
    assert MlL4Proto.from_ip_proto(1) == MlL4Proto.Icmp
    assert MlL4Proto.from_ip_proto(58) == MlL4Proto.Icmp
    assert MlL4Proto.from_ip_proto(132) == MlL4Proto.Sctp
    assert MlL4Proto.from_ip_proto(255) == MlL4Proto.Other


def test_app_proto_values_match_rust():
    assert MlAppProto.Unknown.value == 0
    assert MlAppProto.Tls.value == 1
    assert MlAppProto.Http.value == 2
    assert MlAppProto.Dns.value == 3
    assert MlAppProto.Ssh.value == 4
    assert MlAppProto.Quic.value == 5
    assert MlAppProto.Smtp.value == 6
    assert MlAppProto.Ftp.value == 7
    assert MlAppProto.Rdp.value == 8
    assert MlAppProto.Smb.value == 9
    assert MlAppProto.Other.value == 10


def test_tls_version_values_and_parse():
    assert MlTlsVersion.Tls12.value == 4
    assert MlTlsVersion.Tls13.value == 5
    assert MlTlsVersion.from_raw(0x0303) == MlTlsVersion.Tls12
    assert MlTlsVersion.from_raw(0x0304) == MlTlsVersion.Tls13
    assert MlTlsVersion.from_raw(0x0000) == MlTlsVersion.Unknown


def test_http_method_parsing():
    assert MlHttpMethod.from_str_case_insensitive("get") == MlHttpMethod.Get
    assert MlHttpMethod.from_str_case_insensitive("PROPFIND") == MlHttpMethod.Other
    assert MlHttpMethod.Null.value == 0
    assert MlHttpMethod.Other.value == 8


def test_qtype_values_and_mapping():
    assert MlQtype.A.value == 1
    assert MlQtype.Aaaa.value == 2
    assert MlQtype.Other.value == 14
    assert MlQtype.from_dns_type_code(1) == MlQtype.A
    assert MlQtype.from_dns_type_code(28) == MlQtype.Aaaa
    assert MlQtype.from_dns_type_code(9999) == MlQtype.Other


def test_port_class_buckets():
    assert MlPortClass.from_port(443) == MlPortClass.WellKnown
    assert MlPortClass.from_port(8080) == MlPortClass.Registered
    assert MlPortClass.from_port(50000) == MlPortClass.Dynamic
    assert MlPortClass.from_port(0) == MlPortClass.Unknown
