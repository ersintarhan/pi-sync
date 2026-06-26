/**
 * Minimal SigV4 S3 client. PUT/GET/HEAD/LIST/DELETE — nothing more.
 * ponytail: no AWS SDK, no multipart yet. One signed PUT per object.
 * Tested against IDrive E2 (S3-compatible). Should work on R2/AWS/MinIO too.
 */
import { createHash, createHmac } from "node:crypto";

export interface S3Config {
  /** Full endpoint incl. scheme, e.g. https://pi-sessions.s3.eu-central-1.idrivee2.com */
  endpoint: string;
  bucket: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
}

const sha256 = (s: Buffer | string) =>
  createHash("sha256").update(typeof s === "string" ? Buffer.from(s) : s).digest("hex");

const hmac = (key: Buffer | string, msg: string) =>
  createHmac("sha256", key).update(msg).digest();

/** uri-encode per SigV4 (slash not encoded in path, everything else that must be). */
function encodePath(p: string): string {
  return p.split("/").map((seg) => encodeURIComponent(seg)).join("/");
}
function encodeQueryVal(v: string): string {
  return encodeURIComponent(v).replace(/'/g, "%27");
}

export class S3 {
  host: string;
  base: string;
  constructor(private cfg: S3Config) {
    const u = new URL(cfg.endpoint);
    this.host = u.host;
    this.base = `${u.protocol}//${u.host}`;
  }

  /** Sign one request and fetch it. Returns the Response (caller inspects). */
  private async signed(
    method: string,
    key: string,
    opts: { query?: Record<string, string>; body?: Buffer; contentType?: string; ifNoneMatch?: boolean } = {},
  ): Promise<Response> {
    const amzdate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
    const datestamp = amzdate.slice(0, 8);
    const bodyHash = opts.body ? sha256(opts.body) : sha256("");

    const path = "/" + encodePath(key);
    const queryItems = opts.query
      ? Object.entries(opts.query).sort(([a], [b]) => a.localeCompare(b))
      : [];
    const canonicalQuery = queryItems.map(([k, v]) => `${encodeQueryVal(k)}=${encodeQueryVal(v)}`).join("&");

    const headers: Record<string, string> = {
      host: this.host,
      "x-amz-content-sha256": bodyHash,
      "x-amz-date": amzdate,
    };
    if (opts.contentType) headers["content-type"] = opts.contentType;
    if (opts.ifNoneMatch) headers["if-none-match"] = "*";

    const sortedHeaders = Object.entries(headers).sort(([a], [b]) => a.localeCompare(b));
    const canonicalHeaders = sortedHeaders.map(([k, v]) => `${k}:${v.trim()}\n`).join("");
    const signedHeaders = sortedHeaders.map(([k]) => k).join(";");

    const canonicalRequest = [
      method, path, canonicalQuery, canonicalHeaders, signedHeaders, bodyHash,
    ].join("\n");

    const scope = `${datestamp}/${this.cfg.region}/s3/aws4_request`;
    const stringToSign = [
      "AWS4-HMAC-SHA256", amzdate, scope, sha256(canonicalRequest),
    ].join("\n");

    const kDate = hmac(`AWS4${this.cfg.secretAccessKey}`, datestamp);
    const kRegion = hmac(kDate, this.cfg.region);
    const kService = hmac(kRegion, "s3");
    const kSigning = hmac(kService, "aws4_request");
    const signature = createHmac("sha256", kSigning).update(stringToSign).digest("hex");

    const auth = `AWS4-HMAC-SHA256 Credential=${this.cfg.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    const url = `${this.base}${path}${canonicalQuery ? `?${canonicalQuery}` : ""}`;
    const reqHeaders: Record<string, string> = { ...headers, Authorization: auth };
    // ponytail: fetch BodyInit vs Buffer typing friction; runtime is fine.
    return fetch(url, { method, headers: reqHeaders, body: opts.body as BodyInit });
  }

  async putObject(key: string, body: Buffer, contentType = "application/octet-stream"): Promise<void> {
    const r = await this.signed("PUT", key, { body, contentType });
    if (!r.ok) throw new Error(`PUT ${key} failed: ${r.status} ${await r.text()}`);
  }

  async getObject(key: string): Promise<Buffer | null> {
    const r = await this.signed("GET", key);
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`GET ${key} failed: ${r.status} ${await r.text()}`);
    return Buffer.from(await r.arrayBuffer());
  }

  async headObject(key: string): Promise<{ size: number; etag?: string } | null> {
    const r = await this.signed("HEAD", key);
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`HEAD ${key} failed: ${r.status}`);
    return { size: Number(r.headers.get("content-length") ?? 0), etag: r.headers.get("etag") ?? undefined };
  }

  async listObjects(prefix: string): Promise<{ key: string; size: number }[]> {
    const rr = await this.signed("GET", "", { query: { "list-type": "2", prefix, "max-keys": "1000" } });
    if (!rr.ok) throw new Error(`LIST ${prefix} failed: ${rr.status} ${await rr.text()}`);
    const xml = await rr.text();
    const out: { key: string; size: number }[] = [];
    const re = /<Contents>\s*<Key>([^<]+)<\/Key>[\s\S]*?<Size>(\d+)<\/Size>/g;
    let m;
    while ((m = re.exec(xml))) out.push({ key: m[1], size: Number(m[2]) });
    return out;
  }

  async deleteObject(key: string): Promise<void> {
    const r = await this.signed("DELETE", key);
    if (!r.ok && r.status !== 204) throw new Error(`DELETE ${key} failed: ${r.status} ${await r.text()}`);
  }

  /** Connectivity + credentials sanity check. */
  async ping(): Promise<boolean> {
    const r = await this.signed("HEAD", "");
    return r.ok || r.status === 200;
  }
}
