/**
 * Manifest = change tracking. One encrypted object in S3 (manifest.json) holds
 * the authoritative list of synced sessions + their sha256 + mtime.
 * Local build scans ~/.pi/agent/sessions; remote load GETs+decrypts manifest.json.
 * ponytail: mtime drives last-writer-wins; sha256 drives change detection.
 */
import { createHash } from "node:crypto";
import { readdirSync, statSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { homedir } from "node:os";
import type { S3 } from "./s3.js";
import { seal, open } from "./sync.js";

export interface ManifestEntry {
  /** S3 object key relative to bucket, e.g. sessions/--Users-ersin--/x.jsonl */
  key: string;
  /** sha256 of the PLAINTEXT session file (deterministic change detection). */
  sha256: string;
  /** Plaintext size in bytes (handy for status display). */
  size: number;
  /** File mtime in ms (epoch) — drives last-writer-wins. */
  mtime: number;
}

export interface Manifest {
  version: 1;
  updatedAt: number;
  entries: ManifestEntry[];
}

const MANIFEST_KEY = "manifest.json";
export const SESSIONS_PREFIX = "sessions/";

function fileSha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/** Scan the local sessions dir into a manifest. Returns null if dir missing. */
export function buildLocalManifest(): Manifest | null {
  const root = join(homedir(), ".pi/agent/sessions");
  let dirs: string[];
  try { dirs = readdirSync(root, { withFileTypes: true })
      .filter((d) => d.isDirectory()).map((d) => d.name); }
  catch { return null; }

  const entries: ManifestEntry[] = [];
  for (const dir of dirs) {
    const dirPath = join(root, dir);
    let files: string[];
    try { files = readdirSync(dirPath); } catch { continue; }
    for (const f of files) {
      if (!f.endsWith(".jsonl")) continue;
      const abs = join(dirPath, f);
      // ponytail: posix-style key for S3 (sep normalization)
      const key = (SESSIONS_PREFIX + relative(root, abs)).split(sep).join("/");
      try {
        const st = statSync(abs);
        entries.push({ key, sha256: fileSha256(abs), size: st.size, mtime: st.mtimeMs });
      } catch { /* file vanished mid-scan, skip */ }
    }
  }
  return { version: 1, updatedAt: Date.now(), entries };
}

export function indexBy(entries: ManifestEntry[]): Map<string, ManifestEntry> {
  const m = new Map<string, ManifestEntry>();
  for (const e of entries) m.set(e.key, e);
  return m;
}

/** Diff: what changed between local and remote. Drives push/pull. */
export interface Diff {
  toPush: ManifestEntry[];   // local newer or new → upload
  toPull: ManifestEntry[];   // remote newer or new → download
  toDeleteRemote: string[];  // remote has, local doesn't → delete (push mode)
  upToDate: number;          // unchanged count
}

export function diffManifests(local: Manifest, remote: Manifest | null): Diff {
  const r = remote ? indexBy(remote.entries) : new Map();
  const l = indexBy(local.entries);
  const out: Diff = { toPush: [], toPull: [], toDeleteRemote: [], upToDate: 0 };

  for (const e of local.entries) {
    const rem = r.get(e.key);
    if (!rem) out.toPush.push(e);                       // new locally
    else if (rem.sha256 !== e.sha256) {
      // changed: last-writer-wins by mtime
      if (e.mtime >= rem.mtime) out.toPush.push(e);
      else out.toPull.push(rem);
    } else out.upToDate++;
  }
  if (remote) {
    for (const e of remote.entries) {
      if (!l.has(e.key)) {
        out.toDeleteRemote.push(e.key);                 // exists remote, not local
        // (pull-side: treat as pull candidate too, so user can fetch if they want)
      }
    }
  }
  return out;
}

const enc = (s: string) => Buffer.from(s, "utf-8");

/** Encrypt + PUT the manifest. */
export async function saveRemoteManifest(s3: S3, m: Manifest, key: Buffer): Promise<void> {
  const sealed = seal(enc(JSON.stringify(m)), key);
  await s3.putObject(MANIFEST_KEY, sealed.body, "application/octet-stream");
}

/** GET + decrypt the manifest. Returns null if not present (first push). */
export async function loadRemoteManifest(s3: S3, key: Buffer): Promise<Manifest | null> {
  const got = await s3.getObject(MANIFEST_KEY);
  if (!got) return null;
  const text = open({ body: got }, key).toString("utf-8");
  return JSON.parse(text) as Manifest;
}
