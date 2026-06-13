"""Cross-language conformance: the Python canonicalization MUST reproduce the
record_id that the Go client computed, and MUST match the canonicalization golden
vectors. Run directly (`python3 test_conformance.py`) or under pytest.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))

from canonical import canonicalize, record_id  # noqa: E402

GOLDEN = [
    ({"b": 1, "a": 2}, b'{"a":2,"b":1}'),
    ({"x": [True, False, None, 1]}, b'{"x":[true,false,null,1]}'),
    (chr(1), b'"\\u0001"'),
    ("a\nb", b'"a\\nb"'),
    ('a"b', b'"a\\"b"'),
    ("é→λ", "é→λ".join(['"', '"']).encode("utf-8")),
    ({"o": {}, "a": []}, b'{"a":[],"o":{}}'),
    ({"z": 1, "a": {"y": 2, "b": 3}}, b'{"a":{"b":3,"y":2},"z":1}'),
]


def test_golden_vectors():
    for inp, want in GOLDEN:
        got = canonicalize(inp)
        assert got == want, f"canonicalize({inp!r}) = {got!r}, want {want!r}"


def test_reject_float():
    try:
        canonicalize({"x": 1.5})
    except ValueError:
        return
    raise AssertionError("float was not rejected")


def test_fixture_record_id():
    with open(os.path.join(HERE, "fixture_record.json")) as f:
        rec = json.load(f)
    recomputed = record_id(rec)
    assert recomputed == rec["record_id"], (
        f"Python record_id {recomputed} != Go record_id {rec['record_id']}"
    )


if __name__ == "__main__":
    fns = [test_golden_vectors, test_reject_float, test_fixture_record_id]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
    sys.exit(1 if failed else 0)
