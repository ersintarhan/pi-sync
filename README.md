# @ersintarhan/pi-sync

Encrypted + compressed per-session sync for the [pi coding agent](https://pi.dev). Store your `~/.pi/agent/sessions` on any S3-compatible object storage and pull them on another machine.

Each session JSONL is stored as a **separate** S3 object, wrapped as `AES-256-GCM(gzip(plaintext))`. There's no single huge snapshot blob and no secret-scanning — everything is encrypted at rest.

## Why

`pi` keeps every session locally under `~/.pi/agent/sessions`. If you work across machines (laptop + desktop), those sessions don't follow you. This extension syncs them, encrypted, to object storage you control.

## Setup

### 1. Bucket + credentials

Create a bucket on any S3-compatible storage (IDrive E2, Cloudflare R2, AWS S3, MinIO, …). Grab the endpoint, region, and access keys.

### 2. Config

`~/.pi/agent/pi-sync.local.json`:

```json
{
  "endpoint": "https://pi-sessions.s3.eu-central-1.idrivee2.com",
  "bucket": "pi-sessions",
  "region": "eu-central-1",
  "accessKeyId": "...",
  "secretAccessKey": "..."
}
```

Or set env vars (`PI_SYNC_ENDPOINT`, `PI_SYNC_BUCKET`, `PI_SYNC_REGION`, `PI_SYNC_ACCESS_KEY_ID`, `PI_SYNC_SECRET_ACCESS_KEY`).

### 3. Encryption key

Generate once, then use the **same key on every machine** (keep it out of storage — it never gets synced):

```sh
echo "export PI_SYNC_ENCRYPTION_KEY=\"$(openssl rand -base64 32)\"" >> ~/.zshrc
```

### 4. Install

```sh
pi install npm:@ersintarhan/pi-sync
```

Restart `pi`, then:

```
/pisync doctor
```

— should report `config ok`, `encrypt key ok`, `bucket reachable`.

## Usage

```
/pisync status    # local vs remote diff (dry run)
/pisync push      # upload changed/new local sessions (last-writer-wins)
/pisync pull      # download remote-newer sessions, overwrite local
/pisync doctor    # config + key + connectivity + lock diagnostic
/pisync unlock --stale   # clear a stale lock after a crash
```

On session shutdown, changed sessions are pushed automatically (best-effort).

## Multi-machine workflow

The encryption key is shared, the storage is shared, so each machine stays in sync:

1. Finish work on machine A — sessions auto-push on exit (or run `/pisync push`).
2. Move to machine B — run `/pisync pull` and continue where you left off.

Conflict resolution is **last-writer-wins** by file mtime. Don't run two machines on the same session at once.

## Storage layout

```
<bucket>/
├── manifest.json          # encrypted index: every synced session + sha256 + mtime
└── sessions/
    └── <encoded-cwd>/
        └── *.jsonl        # each session: AES-256-GCM(gzip(plaintext))
```

`manifest.json` drives change detection (sha256) and last-writer-wins (mtime).

## Notes

- No build step — `pi` runs the `.ts` directly.
- No `npm` token needed: releases are published via GitHub Actions OIDC trusted publishing (tag-driven: `npm version patch && git push --tags`).
- Sessions are encrypted at rest, so the bucket can hold API keys that appeared in transcripts. Still — keep your encryption key private and rotate storage keys on suspicion.

MIT.
