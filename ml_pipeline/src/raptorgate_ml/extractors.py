import math
from collections import Counter

ALPN_HASH_BUCKETS = 4096
UA_HASH_BUCKETS = 8192
ZONE_PAIR_HASH_BUCKETS = 256

_FNV1A_OFFSET = 0x811C9DC5
_FNV1A_PRIME = 0x01000193
_U32_MASK = 0xFFFFFFFF


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    h = 0.0
    for count in Counter(data).values():
        p = count / n
        h -= p * math.log2(p)
    return h


def shannon_entropy_str(s: str) -> float:
    return shannon_entropy(s.encode("utf-8"))


def fnv1a(data: bytes) -> int:
    h = _FNV1A_OFFSET
    for b in data:
        h ^= b
        h = (h * _FNV1A_PRIME) & _U32_MASK
    return h


def hash_bucket(s: str, buckets: int) -> int:
    if buckets == 0:
        return 0
    return fnv1a(s.encode("utf-8")) % buckets


def normalized_hash_bucket(s: str, buckets: int) -> float:
    if buckets == 0:
        return 0.0
    return hash_bucket(s, buckets) / buckets


def log1p_f32(x: float) -> float:
    return math.log1p(x)


def label_max_len(qname: str) -> int:
    if not qname:
        return 0
    return max(len(label) for label in qname.split("."))
