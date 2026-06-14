#!/usr/bin/env python3
"""Authoritative, fail-closed validation of donated records.

Run on every contribution: once in the untrusted `pull_request` context (no
secrets) for fast feedback, and again in the trusted merge context before the bot
merges. NEVER trusts client-provided values: it recomputes the record_id, re-checks
the model id, re-runs structural checks, and runs a secret/PII backstop.

Usage:
  validate.py <file.json> [<file.json> ...]
  validate.py --changed changed_files.txt     # one path per line (from `git diff`)

Exit code 0 only if EVERY file passes. Any error, anywhere, fails the whole run.
External secret/PII scanners (gitleaks, trufflehog, Presidio) run as separate CI
steps; this script is the schema/structural/model/hash gate plus a regex backstop.
"""
from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from canonical import record_id  # noqa: E402

SHARD_RE = re.compile(r"^staging/([0-9a-f]{2})/([0-9a-f]{2})/([0-9a-f]{64})\.json$")
INCOMING_RE = re.compile(r"^staging/incoming/[\w.\-]{1,80}\.json$")
MSG_MODEL = "claude-fable-5"
SYNTHETIC = "<synthetic>"
BLOCK_TYPES = {"text", "thinking", "fallback", "tool_use", "tool_result", "image"}
ROLES = {"user", "assistant", "tool"}

# Per-PR / per-record caps.
MAX_FILE_BYTES = 1_000_000
MAX_MESSAGES = 4000
MAX_BLOCK_BYTES = 600_000

# Secret/PII backstop tripwires: presence means the client scrub failed → reject.
TRIPWIRES = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"/Users/[A-Za-z0-9._-]+"),
    re.compile(r"/home/[A-Za-z0-9._-]+"),
    re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
]


class Reject(Exception):
    pass


def load_manifest():
    """Optional: a set of already-ingested record ids (one per line)."""
    seen = set()
    p = os.path.join(HERE, "..", "manifest", "ids.txt")
    if os.path.exists(p):
        with open(p) as f:
            for line in f:
                line = line.strip()
                if line:
                    seen.add(line)
    return seen


def walk_text(blocks):
    for b in blocks:
        t = b.get("type")
        if t in ("text", "thinking", "fallback"):
            yield b.get("text", "")
        elif t == "tool_use":
            yield b.get("name", "")
            yield b.get("input_json", "")
        elif t == "tool_result":
            yield from walk_text(b.get("content", []))
        elif t == "image":
            yield b.get("image", "")


def check_structure(rec):
    if rec.get("schema_version") != "dyc.record.v1":
        raise Reject(f"bad schema_version {rec.get('schema_version')!r}")
    if rec.get("model") != MSG_MODEL:
        raise Reject(f"top-level model must be {MSG_MODEL!r}")
    if rec.get("provenance") != "self-attested":
        raise Reject("provenance must be self-attested")
    if rec.get("license") != "CC0-1.0":
        raise Reject("license must be CC0-1.0")
    if rec.get("dco") is not True:
        raise Reject("dco sign-off flag must be true")

    msgs = rec.get("messages")
    if not isinstance(msgs, list) or not msgs:
        raise Reject("messages must be a non-empty array")
    if len(msgs) > MAX_MESSAGES:
        raise Reject("too many messages")

    tool_use_refs = set()
    tool_result_refs = set()
    fable_seen = False
    for m in msgs:
        role = m.get("role")
        if role not in ROLES:
            raise Reject(f"bad role {role!r}")
        model = m.get("model", "")
        if model == SYNTHETIC:
            raise Reject("synthetic turn present")
        if role == "assistant" and model == MSG_MODEL:
            fable_seen = True
        for b in m.get("blocks", []):
            bt = b.get("type")
            if bt not in BLOCK_TYPES:
                raise Reject(f"bad block type {bt!r}")
            if bt == "tool_use":
                tool_use_refs.add(b.get("ref"))
            if bt == "tool_result":
                tool_result_refs.add(b.get("ref"))
        for text in walk_text(m.get("blocks", [])):
            if len(text) > MAX_BLOCK_BYTES:
                raise Reject("block text exceeds size cap")
    if not fable_seen:
        raise Reject("no genuine claude-fable-5 assistant turn present")
    # Every tool_result must link to a tool_use that exists in this record.
    orphan = tool_result_refs - tool_use_refs - {-1}
    if orphan:
        raise Reject(f"tool_result refs without matching tool_use: {sorted(orphan)}")


def check_secrets(rec):
    blob = "\n".join(t for m in rec.get("messages", []) for t in walk_text(m.get("blocks", [])))
    for rx in TRIPWIRES:
        m = rx.search(blob)
        if m:
            raise Reject(f"secret/PII backstop hit: {rx.pattern[:24]}... (client scrub failed)")


def check_content_address(rec, path):
    rid = rec.get("record_id")
    if not isinstance(rid, str) or not re.fullmatch(r"[0-9a-f]{64}", rid):
        raise Reject("record_id missing or malformed")
    recomputed = record_id(rec)
    if recomputed != rid:
        raise Reject(f"record_id mismatch: file says {rid}, content hashes to {recomputed}")
    m = SHARD_RE.match(path.replace(os.sep, "/"))
    if not m:
        raise Reject(f"path {path} is not a valid shard path")
    if not (m.group(3) == rid and rid.startswith(m.group(1) + m.group(2))):
        raise Reject("shard path does not match record_id")


def validate_file(path, seen):
    rel = path
    # Normalise to the staging/... relative form for the path check.
    idx = path.replace(os.sep, "/").find("staging/")
    if idx >= 0:
        rel = path[idx:]
    relslash = rel.replace(os.sep, "/")
    incoming = bool(INCOMING_RE.match(relslash))
    if not incoming and not SHARD_RE.match(relslash):
        raise Reject(f"path must be staging/incoming/<name>.json or staging/<aa>/<bb>/<id>.json: {rel}")
    size = os.path.getsize(path)
    if size > MAX_FILE_BYTES:
        raise Reject(f"file too large: {size} bytes")
    with open(path, "rb") as f:
        raw = f.read()
    try:
        rec = json.loads(raw)
    except json.JSONDecodeError as e:
        raise Reject(f"invalid JSON: {e}")
    if not isinstance(rec, dict):
        raise Reject("record must be a JSON object")
    check_structure(rec)
    check_secrets(rec)
    if incoming:
        # Agent-built record: the server assigns the content-address id, so we
        # only require the content be clean and well-formed. Compute the id for
        # dedup info; the client need not have provided one.
        rid = record_id(rec)
    else:
        check_content_address(rec, rel)
        rid = rec["record_id"]
    if rid in seen:
        raise Reject("duplicate: record_id already ingested")


def collect_paths(argv):
    if argv and argv[0] == "--changed":
        with open(argv[1]) as f:
            return [ln.strip() for ln in f if ln.strip()]
    return list(argv)


def main(argv):
    paths = collect_paths(argv)
    if not paths:
        print("validate: no files to check", file=sys.stderr)
        return 1
    seen = load_manifest()
    failures = 0
    for p in paths:
        norm = p.replace(os.sep, "/")
        if "staging/" not in norm:
            print(f"REJECT  {p}: PR may only touch staging/** (got non-staging path)")
            failures += 1
            continue
        try:
            validate_file(p, seen)
            print(f"OK      {p}")
        except Reject as e:
            print(f"REJECT  {p}: {e}")
            failures += 1
        except Exception as e:  # fail closed on any unexpected error
            print(f"REJECT  {p}: unexpected error: {e}")
            failures += 1
    print(f"\n{len(paths) - failures}/{len(paths)} passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
