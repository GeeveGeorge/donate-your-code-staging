"""Tests for the authoritative validator: a valid record passes; a tampered one,
a secret-bearing one, and a non-staging path are all rejected (fail closed)."""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "scripts")
sys.path.insert(0, SCRIPTS)
from canonical import record_id  # noqa: E402

VALIDATE = os.path.join(SCRIPTS, "validate.py")


def run(paths):
    return subprocess.run([sys.executable, VALIDATE, *paths], capture_output=True, text=True)


def shard_path(root, rid):
    return os.path.join(root, "staging", rid[:2], rid[2:4], rid + ".json")


def write(path, rec):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(rec, f, indent=2)


def main():
    fixture = json.load(open(os.path.join(HERE, "fixture_record.json")))
    tmp = tempfile.mkdtemp()
    failures = 0

    # 1. Happy path: valid record at its correct shard path passes.
    rid = fixture["record_id"]
    p = shard_path(tmp, rid)
    rec = dict(fixture)
    rec["dco"] = True  # donate sets this before submit
    write(p, rec)
    r = run([p])
    if r.returncode != 0:
        print("FAIL  happy-path:", r.stdout)
        failures += 1
    else:
        print("PASS  happy-path")

    # 2. Tampered content without updating record_id → reject (hash mismatch).
    rec2 = json.loads(json.dumps(rec))
    rec2["messages"][0]["blocks"][0]["text"] = "TAMPERED"
    write(p, rec2)
    r = run([p])
    if r.returncode == 0:
        print("FAIL  tamper not rejected:", r.stdout)
        failures += 1
    else:
        print("PASS  tamper rejected")

    # 3. Secret in content (id recomputed so hash matches) → reject by backstop.
    rec3 = json.loads(json.dumps(rec))
    rec3["messages"][-1]["blocks"][0]["text"] = "leaked AKIAIOSFODNN7EXAMPLE here"
    rec3["record_id"] = record_id(rec3)
    p3 = shard_path(tmp, rec3["record_id"])
    write(p3, rec3)
    r = run([p3])
    if r.returncode == 0 or "backstop" not in r.stdout:
        print("FAIL  secret not caught by backstop:", r.stdout)
        failures += 1
    else:
        print("PASS  secret backstop")

    # 4. Non-staging path → reject.
    other = os.path.join(tmp, "evil.json")
    write(other, rec)
    r = run([other])
    if r.returncode == 0:
        print("FAIL  non-staging path accepted:", r.stdout)
        failures += 1
    else:
        print("PASS  non-staging rejected")

    print(f"\n{4 - failures}/4 checks passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
