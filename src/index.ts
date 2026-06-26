/**
 * pi extension entry. Registers /pisync commands + auto-push on shutdown.
 * ponytail: lock = exclusive-create file + pid-liveness stale check (araklanmış
 * from narumiruna, but stripped to per-session-encrypted model).
 */
import { openSync, closeSync, writeSync, readFileSync, rmSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { loadConfig, pushSync, pullSync, statusSync, doctorSync, type SyncReport } from "./sync.js";

const LOCK_STALE_MS = 30 * 60 * 1000;
const STATE_DIR = join(homedir(), ".pi/agent/.pisync");
const LOCK_PATH = join(STATE_DIR, "lock");

interface LockFile { id: string; pid: number; command: string; startedAt: string }

function ensureStateDir() { mkdirSync(STATE_DIR, { recursive: true }); }

function isStaleLock(lock: LockFile): boolean {
  if (!Number.isInteger(lock.pid) || lock.pid <= 0) return true;
  try { process.kill(lock.pid, 0); return false; }
  catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ESRCH") return true;
    return Date.now() - Date.parse(lock.startedAt) > LOCK_STALE_MS;
  }
}

function readLock(): LockFile | undefined {
  try { return JSON.parse(readFileSync(LOCK_PATH, "utf-8")) as LockFile; }
  catch { return undefined; }
}

/** exclusive-create lock; throws with a useful message if held/stale. */
function withLock<T>(command: string, fn: () => Promise<T>): Promise<T> {
  ensureStateDir();
  const lock: LockFile = { id: randomUUID(), pid: process.pid, command, startedAt: new Date().toISOString() };
  let created = false;
  try {
    const fd = openSync(LOCK_PATH, "wx"); // EEXIST if held
    writeSync(fd, JSON.stringify(lock, null, "\t"));
    closeSync(fd);
    created = true;
    return fn();
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") {
      const cur = readLock();
      if (cur && isStaleLock(cur))
        throw new Error(`pi-sync lock is stale (pid ${cur.pid}). Run /pisync unlock --stale, then retry.`);
      throw new Error(`pi-sync already running${cur ? ` (${cur.command}, pid ${cur.pid})` : ""}.`);
    }
    throw e;
  } finally {
    if (created) { const cur = readLock(); if (cur?.id === lock.id) rmSync(LOCK_PATH, { force: true }); }
  }
}

function fmtReport(r: SyncReport): string {
  const parts = [`pushed ${r.pushed}`, `pulled ${r.pulled}`, `upToDate ${r.upToDate}`];
  if (r.errors.length) parts.push(`❌ ${r.errors.length} errors`);
  return parts.join(", ");
}

export default function syncExtension(pi: ExtensionAPI): void {
  pi.registerCommand("pisync", {
    description: "Encrypted per-session sync (S3/R2). Subcommands: status, push, pull, doctor, unlock.",
    handler: async (rawArgs: string, ctx: any) => {
      const [sub = "status", ...rest] = rawArgs.trim().split(/\s+/);
      const cfg = loadConfig();
      if (!cfg) { ctx.ui.notify?.("❌ No config: set ~/.pi/agent/pi-sync.local.json or PI_SYNC_* env vars.", "error"); return; }

      try {
        if (sub === "status") {
          const st = await withLock("status", () => statusSync(cfg));
          ctx.ui.notify?.(`local: ${st.localCount} | remote: ${st.remoteCount}\ntoPush: ${st.diff.toPush.length} | toPull: ${st.diff.toPull.length} | upToDate: ${st.diff.upToDate}`, "info");
        } else if (sub === "doctor") {
          const d = await doctorSync();
          const cur = readLock();
          const lines = [
            `config:      ${d.configOk ? "ok" : "MISSING"} (${d.configSource})`,
            `encrypt key: ${d.keyOk ? "ok (32-byte)" : "MISSING"}`,
            `bucket:      ${d.pingOk ? "reachable" : "UNREACHABLE"}`,
            `local:       ${d.localCount} sessions`,
            `remote:      ${d.remoteCount} sessions${d.remoteManifest ? "" : " (no manifest yet)"}`,
            `lock:        ${cur ? `held by pid ${cur.pid} (${isStaleLock(cur) ? "STALE" : "live"})` : "free"}`,
          ];
          if (d.errors.length) lines.push(`errors:      ${d.errors.length}`, ...d.errors.slice(0, 3).map((e: string) => `  - ${e}`));
          const healthy = !d.errors.length && d.configOk && d.keyOk && d.pingOk;
          ctx.ui.notify?.(lines.join("\n"), healthy ? "success" : "error");
        } else if (sub === "push") {
          const r = await withLock("push", () => pushSync(cfg));
          ctx.ui.notify?.(`✅ push done — ${fmtReport(r)}`, "success");
        } else if (sub === "pull") {
          const r = await withLock("pull", () => pullSync(cfg));
          ctx.ui.notify?.(`✅ pull done — ${fmtReport(r)}`, "success");
        } else if (sub === "unlock") {
          const cur = readLock();
          if (!cur || !existsSync(LOCK_PATH)) { ctx.ui.notify?.("no lock present", "info"); return; }
          if (rest[0] !== "--stale" && !isStaleLock(cur)) { ctx.ui.notify?.("lock is NOT stale; pass --stale to force", "warn"); return; }
          rmSync(LOCK_PATH, { force: true });
          ctx.ui.notify?.(`✅ removed lock (pid ${cur.pid})`, "success");
        } else {
          ctx.ui.notify?.(`unknown '${sub}'. Use: status, push, pull, doctor, unlock.`, "warn");
        }
      } catch (e) {
        ctx.ui.notify?.(`❌ ${String((e as Error).message ?? e)}`, "error");
      }
    },
  });

  // Auto-push sessions when the session ends (unless it's just a reload).
  pi.on("session_shutdown", async (event) => {
    const reason = typeof event === "object" && event ? (event as { reason?: string }).reason : undefined;
    if (reason === "reload") return;
    const cfg = loadConfig();
    if (!cfg || !process.env.PI_SYNC_ENCRYPTION_KEY) return;
    try { await withLock("auto-push", () => pushSync(cfg)); }
    catch { /* auto-push is best-effort; don't block shutdown */ }
  });
}
