/**
 * @ersintarhan/pi-sync — encrypted + compressed per-session sync.
 *
 * Storage model: each session JSONL is a SEPARATE S3 object, wrapped as
 *   AES-256-GCM(gzip(plaintext)).
 * No single snapshot blob (avoids the 133MB one-PUT problem), no secret
 * scanning (everything is encrypted at rest).
 *
 * ponytail: this file holds the crypto foundation + a runnable self-check.
 * S3 client / manifest / sync loop get layered on after the roundtrip proves out.
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { gzipSync, gunzipSync } from "node:zlib";
import { homedir } from "node:os";
import { S3, type S3Config } from "./s3.js";
import {
  buildLocalManifest, loadRemoteManifest, saveRemoteManifest, diffManifests,
  SESSIONS_PREFIX, type Manifest, type Diff,
} from "./manifest.js";
import { readFileSync, writeFileSync, mkdirSync, utimesSync } from "node:fs";
import { join, dirname } from "node:path";

/** One encrypted blob = nonce(12) + ciphertext + tag(16). Key derived/kept externally. */
export interface Sealed {
  /** Raw bytes: nonce || ciphertext || tag. Ready to PUT as a single S3 object body. */
  body: Buffer;
}

/**
 * Encrypt + compress. Order matters: compress first (plaintext compresses
 * far better than ciphertext), then encrypt. GCM gives authenticated encryption
 * — tampering is detected on decrypt.
 */
export function seal(plaintext: Buffer, key: Buffer): Sealed {
  if (key.length !== 32) throw new Error(`AES-256 needs a 32-byte key, got ${key.length}`);
  const nonce = randomBytes(12); // 96-bit nonce, never reuse with same key
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const gz = gzipSync(plaintext);
  const enc = Buffer.concat([cipher.update(gz), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes
  return { body: Buffer.concat([nonce, enc, tag]) };
}

/** Decrypt + decompress. Throws if key is wrong or blob was tampered (GCM auth fails). */
export function open(sealed: Sealed, key: Buffer): Buffer {
  if (key.length !== 32) throw new Error(`AES-256 needs a 32-byte key, got ${key.length}`);
  const nonce = sealed.body.subarray(0, 12);
  const tag = sealed.body.subarray(sealed.body.length - 16);
  const enc = sealed.body.subarray(12, sealed.body.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  const gz = Buffer.concat([decipher.update(enc), decipher.final()]);
  return gunzipSync(gz);
}

/** Derive a 32-byte key from a base64 env string (the PI_SYNC_ENCRYPTION_KEY value). */
export function keyFromEnv(raw: string): Buffer {
  const buf = Buffer.from(raw.trim(), "base64");
  if (buf.length !== 32) throw new Error(`PI_SYNC_ENCRYPTION_KEY must decode to 32 bytes, got ${buf.length}. Generate with: openssl rand -base64 32`);
  return buf;
}

/** Load S3 config from ~/.pi/agent/pi-sync.local.json, with PI_SYNC_* env overrides. */
export function loadConfig(): S3Config | null {
  const env = process.env;
  const file = join(homedir(), ".pi/agent/pi-sync.local.json");
  let f: Partial<S3Config> = {};
  try { f = JSON.parse(readFileSync(file, "utf-8")); } catch { /* no file */ }
  const get = (k: string, envKey: string): string | undefined =>
    (env[envKey] as string | undefined) ?? (f as Record<string, string | undefined>)[k];
  const endpoint = get("endpoint", "PI_SYNC_ENDPOINT");
  const bucket = get("bucket", "PI_SYNC_BUCKET");
  const region = get("region", "PI_SYNC_REGION");
  const accessKeyId = get("accessKeyId", "PI_SYNC_ACCESS_KEY_ID");
  const secretAccessKey = get("secretAccessKey", "PI_SYNC_SECRET_ACCESS_KEY");
  if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) return null;
  return { endpoint, bucket, region: region ?? "auto", accessKeyId, secretAccessKey };
}

export function keyFromEnvOrThrow(): Buffer {
  const raw = process.env.PI_SYNC_ENCRYPTION_KEY;
  if (!raw) throw new Error("PI_SYNC_ENCRYPTION_KEY not set. Generate with: openssl rand -base64 32");
  return keyFromEnv(raw);
}

const ENC_UTF8 = (s: string) => Buffer.from(s, "utf-8");

function localPathFor(key: string): string {
  // S3 key 'sessions/<rel>' -> ~/.pi/agent/sessions/<rel>
  const rel = key.startsWith(SESSIONS_PREFIX) ? key.slice(SESSIONS_PREFIX.length) : key;
  // ponytail: defense-in-depth — manifest is GCM-authed so hard to tamper, but a
  // crafted key ('sessions/../../etc/foo') must not escape the sessions dir.
  if (rel.split(/[\\/]/).some((seg) => seg === "..")) throw new Error(`unsafe path: ${key}`);
  return join(homedir(), ".pi/agent/sessions", rel);
}

export interface SyncReport {
  pushed: number; pulled: number; upToDate: number;
  errors: string[];
}

/** Push: upload changed/new local sessions (last-writer-wins), refresh remote manifest. */
export async function pushSync(cfg: S3Config): Promise<SyncReport> {
  const s3 = new S3(cfg);
  const key = keyFromEnvOrThrow();
  const local = buildLocalManifest();
  if (!local) throw new Error("no local sessions dir (~/.pi/agent/sessions)");
  const remote = await loadRemoteManifest(s3, key);
  const d = diffManifests(local, remote);
  const report: SyncReport = { pushed: 0, pulled: 0, upToDate: d.upToDate, errors: [] };

  for (const e of d.toPush) {
    try {
      const plain = readFileSync(localPathFor(e.key));
      await s3.putObject(e.key, seal(plain, key).body);
      report.pushed++;
    } catch (err) { report.errors.push(`push ${e.key}: ${String(err)}`); }
  }
  // ponytail: don't save the manifest if any PUT failed — otherwise the manifest
  // would claim files are synced that aren't in S3, and a pull elsewhere would 404.
  // Retry is idempotent (sha-based diff), so aborting here stays consistent.
  if (report.errors.length) return report;
  // ponytail: remote-only files → leave them (don't auto-delete; safer). Manifest keeps them.
  // Rebuild manifest from local view + any remote entries we didn't touch.
  const kept = remote ? remote.entries.filter((re) => !local.entries.some((le) => le.key === re.key)) : [];
  const merged: Manifest = { ...local, entries: [...local.entries, ...kept] };
  await saveRemoteManifest(s3, merged, key);
  return report;
}

/** Pull: download remote-newer sessions, overwrite local (last-writer-wins). */
export async function pullSync(cfg: S3Config): Promise<SyncReport> {
  const s3 = new S3(cfg);
  const key = keyFromEnvOrThrow();
  const local = buildLocalManifest();
  const remote = await loadRemoteManifest(s3, key);
  if (!remote) throw new Error("remote manifest not found — nothing to pull");
  const d = diffManifests(local ?? { version: 1, updatedAt: 0, entries: [] }, remote);
  const report: SyncReport = { pushed: 0, pulled: 0, upToDate: d.upToDate, errors: [] };

  for (const e of d.toPull) {
    try {
      const got = await s3.getObject(e.key);
      if (!got) { report.errors.push(`pull ${e.key}: 404`); continue; }
      const plain = open({ body: got }, key);
      const dest = localPathFor(e.key);
      mkdirSync(dirname(dest), { recursive: true });
      writeFileSync(dest, plain);
      // ponytail: restore the original source mtime so local mtime == remote manifest
      // mtime (otherwise writeFileSync stamps now(), splitting the two views).
      utimesSync(dest, e.mtime / 1000, e.mtime / 1000);
      report.pulled++;
    } catch (err) { report.errors.push(`pull ${e.key}: ${String(err)}`); }
  }
  return report;
}

/** Status: show local vs remote diff without changing anything. */
export async function statusSync(cfg: S3Config): Promise<{ diff: Diff; localCount: number; remoteCount: number }> {
  const s3 = new S3(cfg);
  const key = keyFromEnvOrThrow();
  const local = buildLocalManifest() ?? { version: 1 as const, updatedAt: 0, entries: [] };
  const remote = await loadRemoteManifest(s3, key);
  return {
    diff: diffManifests(local, remote),
    localCount: local.entries.length,
    remoteCount: remote?.entries.length ?? 0,
  };
}

export interface DoctorReport {
  configOk: boolean;
  configSource: "file" | "env" | "none";
  keyOk: boolean;
  pingOk: boolean;
  remoteManifest: boolean;
  remoteCount: number;
  localCount: number;
  errors: string[];
}

/** Doctor: read-only diagnostic. No lock, no writes. */
export async function doctorSync(): Promise<DoctorReport> {
  const rep: DoctorReport = {
    configOk: false, configSource: "none", keyOk: false, pingOk: false,
    remoteManifest: false, remoteCount: 0, localCount: 0, errors: [],
  };

  // config: detect source (file vs env)
  const hasFile = (() => { try { return Boolean(readFileSync(join(homedir(), ".pi/agent/pi-sync.local.json"), "utf-8")); } catch { return false; } })();
  const hasEnv = Boolean(process.env.PI_SYNC_ENDPOINT && process.env.PI_SYNC_ACCESS_KEY_ID);
  const cfg = loadConfig();
  rep.configSource = hasFile ? "file" : hasEnv ? "env" : "none";
  if (!cfg) { rep.errors.push("config missing (need ~/.pi/agent/pi-sync.local.json or PI_SYNC_* env)"); return rep; }
  rep.configOk = true;

  // encryption key
  try { keyFromEnvOrThrow(); rep.keyOk = true; }
  catch (e) { rep.errors.push(`PI_SYNC_ENCRYPTION_KEY: ${(e as Error).message}`); }

  // local sessions
  const local = buildLocalManifest();
  rep.localCount = local?.entries.length ?? 0;
  if (!local) rep.errors.push("no local sessions dir (~/.pi/agent/sessions)");

  // remote: ping + manifest. Skip if key is bad (can't decrypt manifest).
  if (!rep.keyOk) return rep;
  const s3 = new S3(cfg);
  try { rep.pingOk = await s3.ping(); }
  catch (e) { rep.errors.push(`ping ${cfg.endpoint}: ${(e as Error).message}`); return rep; }
  if (!rep.pingOk) { rep.errors.push("bucket unreachable"); return rep; }
  try {
    const remote = await loadRemoteManifest(s3, keyFromEnvOrThrow());
    rep.remoteManifest = Boolean(remote);
    rep.remoteCount = remote?.entries.length ?? 0;
  } catch (e) { rep.errors.push(`manifest load: ${(e as Error).message}`); }

  return rep;
}

// --- ponytail: runnable self-check. Crypto always; S3 roundtrip if configured. ---
if (import.meta.url === `file://${process.argv[1]}`) {
  (async () => {
  const key = randomBytes(32);
  const sample = Buffer.from(JSON.stringify({
    role: "user",
    content: "OPENAI_API_KEY=sk-" + "x".repeat(48) + " — should be invisible in storage",
  }) + "\n".repeat(5000)); // force some size so compression is meaningful

  const sealed = seal(sample, key);
  const recovered = open(sealed, key);
  const ok = sample.equals(recovered);

  console.log("=== pi-sync crypto self-check ===");
  console.log(`plaintext:   ${sample.length} bytes`);
  console.log(`sealed:      ${sealed.body.length} bytes  (ratio ${(sealed.body.length / sample.length * 100).toFixed(1)}%)`);
  console.log(`sealed head: ${sealed.body.subarray(0, 16).toString("hex")} (nonce + start of ciphertext — NOT plaintext)`);
  console.log(`roundtrip:   ${ok ? "✅ OK" : "❌ MISMATCH"}`);
  console.log(`tamper test: ${(() => {
    const tampered = Buffer.from(sealed.body); tampered[50] ^= 0xff;
    try { open({ body: tampered }, key); return "❌ tamper NOT detected"; }
    catch { return "✅ tamper rejected (GCM auth)"; }
  })()}`);
  if (!ok) process.exit(1);

  // --- ponytail: diff self-check — remote-only MUST land in toPull (the fix). ---
  {
    const local: Manifest = { version: 1, updatedAt: 0, entries: [
      { key: "sessions/a/shared.jsonl", sha256: "h1", size: 10, mtime: 100 },
    ] };
    const remote: Manifest = { version: 1, updatedAt: 0, entries: [
      { key: "sessions/a/shared.jsonl", sha256: "h1", size: 10, mtime: 100 },
      { key: "sessions/a/remote-only.jsonl", sha256: "h2", size: 20, mtime: 200 },
    ] };
    const d = diffManifests(local, remote);
    const pulled = d.toPull.map((e) => e.key).includes("sessions/a/remote-only.jsonl");
    console.log("\n=== pi-sync diff self-check ===");
    console.log(`toPull: ${d.toPull.map((e) => e.key).join(", ") || "(empty)"}`);
    console.log(`remote-only pulled: ${pulled ? "✅ OK" : "❌ MISSING — pull would skip deleted/new sessions"}`);
    if (!pulled) process.exit(1);
  }

  // --- S3 roundtrip: only if config + key are present. End-to-end: seal -> PUT -> GET -> open ---
  const cfg = loadConfig();
  const envKey = process.env.PI_SYNC_ENCRYPTION_KEY;
  if (cfg && envKey) {
    console.log("\n=== S3 roundtrip (end-to-end) ===");
    const s3 = new S3(cfg);
    const k = keyFromEnv(envKey);
    const objKey = "pi-sync/_selftest/roundtrip.bin";
    const payload = Buffer.from("pi-sync end-to-end test " + new Date().toISOString());
    const sealedPayload = seal(payload, k);
    console.log(`ping:        ${await s3.ping() ? "✅ reachable" : "❌ unreachable"}`);
    await s3.putObject(objKey, sealedPayload.body);
    console.log(`PUT:         ✅ ${objKey} (${sealedPayload.body.length} bytes encrypted)`);
    const got = await s3.getObject(objKey);
    if (!got) { console.log("GET:         ❌ not found after PUT"); process.exit(1); }
    const recovered = open({ body: got }, k);
    const e2eOk = payload.equals(recovered);
    console.log(`GET+decrypt: ${e2eOk ? "✅ roundtrip OK" : "❌ MISMATCH"}`);
    await s3.deleteObject(objKey);
    console.log(`cleanup:     ✅ deleted ${objKey}`);
    if (!e2eOk) process.exit(1);
  } else {
    console.log("\n(skip S3 roundtrip: set PI_SYNC_ENCRYPTION_KEY + ~/.pi/agent/pi-sync.local.json to enable)");
  }

  // --- SYNC roundtrip: push real local sessions, then status ---
  const cfg2 = loadConfig();
  if (cfg2 && process.env.PI_SYNC_ENCRYPTION_KEY) {
    console.log("\n=== sync push (real local sessions → IDrive) ===");
    const report = await pushSync(cfg2);
    console.log(`pushed: ${report.pushed}, upToDate: ${report.upToDate}, errors: ${report.errors.length}`);
    if (report.errors.length) console.log("  errors:", report.errors.slice(0, 3));
    console.log("\n=== sync status (local vs remote) ===");
    const st = await statusSync(cfg2);
    console.log(`local: ${st.localCount} sessions, remote: ${st.remoteCount}`);
    console.log(`toPush: ${st.diff.toPush.length}, toPull: ${st.diff.toPull.length}, upToDate: ${st.diff.upToDate}`);
  }
  })().catch((e) => { console.error(e); process.exit(1); });
}