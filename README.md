# @ersintarhan/pi-sync

Encrypted + compressed per-session sync for the [pi coding agent](https://pi.dev).

Each session JSONL is stored as a **separate** S3 object, encrypted with AES-256-GCM and gzip-compressed. No single huge snapshot blob, no secret-scanning (everything is encrypted at rest).

## Config

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

Encryption key via env (never synced):
```sh
export PI_SYNC_ENCRYPTION_KEY="$(openssl rand -base64 32)"
```

WIP — see `src/sync.ts`.
