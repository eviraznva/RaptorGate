from raptorgate_ml.extractors import (
    hash_bucket,
    label_max_len,
    log1p_f32,
    shannon_entropy,
    shannon_entropy_str,
)


def test_entropy_uniform_higher_than_repeat():
    assert shannon_entropy_str("abcdefgh") > shannon_entropy_str("aaaaaaaa")


def test_entropy_empty_zero():
    assert shannon_entropy(b"") == 0.0


def test_hash_bucket_stable():
    a = hash_bucket("example.com", 4096)
    b = hash_bucket("example.com", 4096)
    assert a == b
    assert 0 <= a < 4096


def test_label_max():
    assert label_max_len("a.bbb.cc") == 3
    assert label_max_len("") == 0


def test_log1p_zero():
    assert log1p_f32(0.0) == 0.0


def test_entropy_repeat_is_zero():
    assert shannon_entropy_str("aaaaaaaa") == 0.0


def test_hash_bucket_zero_buckets_returns_zero():
    assert hash_bucket("x", 0) == 0
