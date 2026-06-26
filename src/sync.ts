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

// --- ponytail: one runnable self-check. Fails loudly if roundtrip breaks. ---
if (import.meta.url === `file://${process.argv[1]}`) {
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
}
