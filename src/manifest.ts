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

/** pi encodes cwd as --{cwd.replace(/^[/\\]/,"").replace(/[/\\:]/g,"-")}--.
 *  homeDirInner mirrors that transform for the home prefix so we can split it off. */
export function homeDirInner(h: string = homedir()): string {
  return h.replace(/^[/\\]/, "").replace(/[/\\:]/g, "-");
}

/** Normalize a pi-encoded cwd dir name so the same project yields the same S3
 *  key across OSes: /Users/x/proj (mac) and /home/x/proj (linux) both → ~-proj.
 *  Paths outside home (e.g. /tmp, which mac resolves to /private/tmp) can't be
 *  reconciled across OSes and are left OS-native. */
export function normalizeDirName(dirName: string, homeInner: string = homeDirInner()): string {
  const inner = dirName.replace(/^--/, "").replace(/--$/, "");
  if (inner === homeInner) return "~";
  if (inner.startsWith(homeInner + "-")) return "~-" + inner.slice(homeInner.length + 1);
  return dirName; // outside home — keep OS-native (can't reconcile)
}

/** Inverse of normalizeDirName: ~ (or ~-rest) → this machine's pi-encoded home dir. */
export function denormalizeDirName(norm: string, homeInner: string = homeDirInner()): string {
  if (norm === "~") return "--" + homeInner + "--";
  if (norm.startsWith("~-")) return "--" + homeInner + norm.slice(1) + "--"; // ~ at [0] → -
  return norm;
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
      // ponytail: posix key + cross-OS home normalize (mac /Users/x, linux /home/x → ~)
      const rel = relative(root, abs).split(sep).join("/");
      const slash = rel.indexOf("/");
      const dirName = slash >= 0 ? rel.slice(0, slash) : rel;
      const tail = slash >= 0 ? rel.slice(slash) : "";
      const key = SESSIONS_PREFIX + normalizeDirName(dirName) + tail;
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
  toPull: ManifestEntry[];   // remote newer OR remote-only → download
  upToDate: number;          // unchanged count
}

export function diffManifests(local: Manifest, remote: Manifest | null): Diff {
  const r = remote ? indexBy(remote.entries) : new Map();
  const l = indexBy(local.entries);
  const out: Diff = { toPush: [], toPull: [], upToDate: 0 };

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
      // ponytail: remote-only (local deleted it, or fresh machine) → pull it down.
      // Deletion doesn't propagate via push (push leaves them), so remote wins = fetch.
      if (!l.has(e.key)) out.toPull.push(e);
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
