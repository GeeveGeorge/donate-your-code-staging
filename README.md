# donate-your-code-staging

The **vetting + queue** repository for [Donate Your Code](https://github.com/GeeveGeorge/donate-your-code).
This is where the `dyc` client opens contribution Pull Requests. GitHub Actions is
the authoritative gate; a bot auto-merges what passes; an hourly job compacts merged
records into the canonical **Hugging Face** Parquet dataset and then prunes them
here so this repo stays small.

```
contributor --PR (own token)--> staging/<aa>/<bb>/<id>.json
        │
        ├─ validate.yml   (untrusted: pull_request, read-only, NO secrets) → fast feedback
        ├─ gatekeeper.yml (trusted: workflow_run → re-validate at pinned SHA → squash-merge)
        └─ compact.yml    (hourly, trusted: re-validate → Parquet → ONE Hugging Face commit → prune)
```

## What's enforced (fail closed)

A contribution PR may **only add** files matching
`staging/<aa>/<bb>/<sha256>.json`. Anything else is auto-rejected. Each record is
re-validated server-side from scratch (never trusting the client):

- strict structure, roles, and block types; size caps
- top-level `model == claude-fable-5`; at least one genuine Fable 5 assistant turn;
  no `<synthetic>` turns
- **content-address recompute**: `record_id` must equal `sha256(canonical(content))`
  AND the filename AND the shard path (defeats hash/path spoofing)
- tool_use ↔ tool_result ref linkage
- a secret/PII backstop (`/Users/`, emails, AWS/GitHub keys, private-key blocks)
  plus a gitleaks step — presence means the client scrub failed → reject
- exact-duplicate rejection via the manifest

The workflows, scripts, schema, and manifest are CODEOWNERS-gated, and the merge
bot has no `workflows` permission — so **code/backdoors cannot be introduced via the
contribution path**.

## Layout

```
staging/<aa>/<bb>/<id>.json      contribution records (transient; pruned after compaction)
scripts/canonical.py             RFC 8785 canonicalization + record_id (mirrors the Go client)
scripts/validate.py              the authoritative gate
scripts/compact.py               drain → Parquet → Hugging Face → prune
schema/record.schema.json        record schema (copy from the tooling repo)
manifest/ids.txt                 ingested record ids (dedup high-water mark; bot-only)
.github/workflows/*.yml          validate / gatekeeper / compact (SHA-pinned)
.github/CODEOWNERS               non-data paths are maintainer-only
```

See the tooling repo's `deploy/DEPLOY.md` for one-time setup (secrets, branch
protection, the Hugging Face dataset).
