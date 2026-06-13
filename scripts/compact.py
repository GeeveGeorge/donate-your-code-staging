#!/usr/bin/env python3
"""Compaction: drain merged staging records into the canonical dataset.

Runs hourly in the TRUSTED context (it holds the HF token). It re-validates every
record from scratch, dedups against the manifest, appends to hash-sharded Parquet,
optionally pushes one commit to a Hugging Face dataset, updates the manifest, and
removes the drained staging files. Idempotent: the manifest is the high-water mark,
so a crashed run is safely re-run.

Env:
  HF_DATASET   e.g. "GeeveGeorge/donate-your-code"  (optional; local-only if unset)
  HF_TOKEN     Hugging Face write token              (required to push)

Parquet via pyarrow; falls back to JSONL shards if pyarrow is unavailable so the
job still makes progress. The manifest (manifest/ids.txt) is authoritative.
"""
from __future__ import annotations

import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from canonical import record_id  # noqa: E402
import validate as V  # noqa: E402

ROOT = os.path.abspath(os.path.join(HERE, ".."))
MANIFEST = os.path.join(ROOT, "manifest", "ids.txt")


def load_seen():
    seen = set()
    if os.path.exists(MANIFEST):
        with open(MANIFEST) as f:
            seen = {ln.strip() for ln in f if ln.strip()}
    return seen


def append_manifest(ids):
    os.makedirs(os.path.dirname(MANIFEST), exist_ok=True)
    with open(MANIFEST, "a") as f:
        for i in ids:
            f.write(i + "\n")


def flatten_row(rec):
    """One flat row for the dataset (content kept; raw PII already scrubbed)."""
    return {
        "record_id": rec["record_id"],
        "schema_version": rec["schema_version"],
        "model": rec["model"],
        "provenance": rec.get("provenance", "self-attested-unverified"),
        "is_subagent": bool(rec.get("is_subagent", False)),
        "models_present": ",".join(rec.get("models_present", [])),
        "claude_code_version": rec.get("claude_code_version", ""),
        "contributor": rec.get("contributor", ""),
        "messages_json": json.dumps(rec.get("messages", []), separators=(",", ":")),
        "n_messages": len(rec.get("messages", [])),
    }


def write_shard(rows_by_shard):
    """Append rows to hash-sharded Parquet (or JSONL fallback)."""
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
        use_parquet = True
    except Exception:
        use_parquet = False

    for (aa, bb), rows in rows_by_shard.items():
        d = os.path.join(ROOT, "data", aa, bb)
        os.makedirs(d, exist_ok=True)
        if use_parquet:
            path = os.path.join(d, "part.parquet")
            table = pa.Table.from_pylist(rows)
            if os.path.exists(path):
                existing = pq.read_table(path)
                table = pa.concat_tables([existing, table])
            pq.write_table(table, path)
        else:
            path = os.path.join(d, "part.jsonl")
            with open(path, "a") as f:
                for r in rows:
                    f.write(json.dumps(r) + "\n")


def push_to_hf(changed_dirs):
    dataset = os.environ.get("HF_DATASET")
    token = os.environ.get("HF_TOKEN")
    if not dataset or not token:
        print("HF_DATASET/HF_TOKEN not set — wrote dataset locally only.")
        return
    try:
        from huggingface_hub import HfApi, CommitOperationAdd
    except Exception as e:
        print(f"huggingface_hub unavailable ({e}); local write only.")
        return
    api = HfApi(token=token)
    ops = []
    for rel in changed_dirs:
        for fn in glob.glob(os.path.join(ROOT, rel, "*")):
            ops.append(CommitOperationAdd(path_in_repo=os.path.relpath(fn, ROOT), path_or_fileobj=fn))
    ops.append(CommitOperationAdd(path_in_repo="manifest/ids.txt", path_or_fileobj=MANIFEST))
    api.create_commit(repo_id=dataset, repo_type="dataset", operations=ops,
                      commit_message="compaction: add validated Fable 5 records")
    print(f"Pushed {len(ops)} file(s) to hf://datasets/{dataset}")


def main():
    seen = load_seen()
    files = sorted(glob.glob(os.path.join(ROOT, "staging", "*", "*", "*.json")))
    rows_by_shard = {}
    new_ids = []
    drained = []
    quarantined = []
    for p in files:
        rel = "staging/" + "/".join(p.split(os.sep)[-3:])
        try:
            V.validate_file(p, seen)  # re-validate from scratch
            rec = json.load(open(p))
            rid = rec["record_id"]
            if record_id(rec) != rid or rid in seen:
                drained.append(p)
                continue
            aa, bb = rid[:2], rid[2:4]
            rows_by_shard.setdefault((aa, bb), []).append(flatten_row(rec))
            new_ids.append(rid)
            seen.add(rid)
            drained.append(p)
        except Exception as e:  # never publish; quarantine for review
            print(f"QUARANTINE {rel}: {e}")
            quarantined.append(p)

    if not new_ids:
        print(f"Nothing new to compact ({len(quarantined)} quarantined).")
        return 0

    write_shard(rows_by_shard)
    changed_dirs = {f"data/{aa}/{bb}" for (aa, bb) in rows_by_shard}
    append_manifest(new_ids)
    push_to_hf(changed_dirs)

    # Only after the records are safely in the manifest do we remove staging files.
    for p in drained:
        if p not in quarantined:
            try:
                os.remove(p)
            except OSError:
                pass
    print(f"Compacted {len(new_ids)} record(s) into {len(changed_dirs)} shard(s); "
          f"{len(quarantined)} quarantined.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
