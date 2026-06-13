"""RFC 8785 (JCS) canonicalization and content-addressed record_id.

This MUST stay byte-for-byte identical to the Go client's
internal/record/canonical.go and the preimage in internal/record/record.go.
See schema/canonicalization.md. Cross-language conformance is enforced by
tests/test_conformance.py against a fixture produced by the Go binary.
"""
from __future__ import annotations

import hashlib
from typing import Any


def _enc_string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\b':
            out.append('\\b')
        elif ch == '\t':
            out.append('\\t')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\f':
            out.append('\\f')
        elif ch == '\r':
            out.append('\\r')
        elif o < 0x20:
            out.append('\\u%04x' % o)
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def canonicalize(v: Any) -> bytes:
    """Return the canonical UTF-8 bytes of a restricted JSON value tree.

    Allowed leaf types: None, bool, int, str. Floats are rejected (the preimage
    contains no floats; tool inputs are pre-serialized to opaque strings)."""
    return _canon(v).encode("utf-8")


def _canon(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _enc_string(v)
    if isinstance(v, bool):  # unreachable (handled above) but explicit
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        raise ValueError("float not allowed in canonical preimage; use int or a pre-serialized string")
    if isinstance(v, list):
        return "[" + ",".join(_canon(e) for e in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys())  # ASCII keys: byte order == code-point order
        return "{" + ",".join(_enc_string(k) + ":" + _canon(v[k]) for k in keys) + "}"
    raise TypeError(f"canonicalize: unsupported type {type(v).__name__}")


def _ref_val(r: Any) -> int:
    return -1 if r is None else int(r)


def _block_preimage(b: dict) -> dict:
    t = b.get("type")
    if t == "tool_use":
        return {
            "type": "tool_use",
            "ref": _ref_val(b.get("ref")),
            "name": b.get("name", ""),
            "input_json": b.get("input_json", ""),
        }
    if t == "tool_result":
        return {
            "type": "tool_result",
            "ref": _ref_val(b.get("ref")),
            "is_error": bool(b.get("is_error", False)),
            "truncated": bool(b.get("truncated", False)),
            "content": [_block_preimage(x) for x in b.get("content", [])],
        }
    if t == "image":
        return {"type": "image", "image": b.get("image", "")}
    return {"type": t, "text": b.get("text", "")}


def build_preimage(rec: dict) -> dict:
    """Build the content-only preimage from a full record dict (matches Go)."""
    msgs = []
    for m in rec.get("messages", []):
        u = m.get("usage") or {}
        msgs.append({
            "role": m.get("role", ""),
            "model": m.get("model", ""),
            "stop_reason": m.get("stop_reason", ""),
            "usage": {
                "cache_creation_input_tokens": int(u.get("cache_creation_input_tokens", 0)),
                "cache_read_input_tokens": int(u.get("cache_read_input_tokens", 0)),
                "service_tier": u.get("service_tier", ""),
            },
            "blocks": [_block_preimage(b) for b in m.get("blocks", [])],
        })
    return {
        "schema_version": rec["schema_version"],
        "model": rec["model"],
        "messages": msgs,
    }


def record_id(rec: dict) -> str:
    """Recompute the content-addressed record id from a full record dict."""
    return hashlib.sha256(canonicalize(build_preimage(rec))).hexdigest()
