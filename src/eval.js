// Parallel evaluation engine for jev-guard.
// Compares primary model decisions against a shadow model concurrently,
// logging telemetry to ~/.jev-guard/eval.jsonl without blocking or failing guard decisions.

import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { appendFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { ask, backend, DEFAULT_MODEL, readConfig, resolveBackend } from "./jev.js";

export const EVAL_FILE = join(homedir(), ".jev-guard", "eval.jsonl");

/** Returns the path to eval.jsonl, honoring the JEV_GUARD_EVAL_FILE environment override if present. */
export const evalConfigFile = (env = process.env) => env.JEV_GUARD_EVAL_FILE ?? EVAL_FILE;

/**
 * Redacts common sensitive patterns (API keys, bearer tokens, passwords) from preview strings.
 * @param {string} text - Raw preview string
 * @returns {string} Sanitized string
 */
export function redactSecrets(text) {
  if (!text || typeof text !== "string") return "";
  return text
    .replace(/(Bearer\s+)[A-Za-z0-9_.-]+/gi, "$1[REDACTED]")
    .replace(/(vck_[A-Za-z0-9_.-]{10,}|sk-or-[A-Za-z0-9_.-]{10,}|sk-[A-Za-z0-9_.-]{20,})/g, "[REDACTED_KEY]")
    .replace(/(?:password|secret|passwd|token|apiKey|api_key)\s*[:=]\s*["']?[^"'\s,;]+["']?/gi, (match) => {
      const idx = match.search(/[:=]/);
      return match.slice(0, idx + 1) + " [REDACTED]";
    })
    .replace(/-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----/g, "[REDACTED_PRIVATE_KEY]");
}

/**
 * Resolves the shadow model and backend configuration from config and environment.
 * @param {Object} [cfg] - Parsed configuration object
 * @param {NodeJS.ProcessEnv} [env=process.env] - Environment variables object
 * @returns {{model: string, backend: string}|null} Shadow configuration or null if not enabled
 */
export function resolveShadow(cfg, env = process.env) {
  const c = cfg ?? readConfig(env);
  const rawModel = env.JEV_SHADOW_MODEL ?? c.shadowModel ?? c.shadow?.model;
  if (!rawModel || rawModel === "off" || rawModel === "none" || rawModel === "false") return null;

  let rawBackend = env.JEV_SHADOW_BACKEND ?? c.shadowBackend ?? c.shadow?.backend;
  if (!rawBackend) {
    if (rawModel.includes("/")) rawBackend = "openrouter";
    else {
      const active = backend(env);
      rawBackend = active?.kind ?? "openrouter";
    }
  }
  return { model: String(rawModel).trim(), backend: String(rawBackend).toLowerCase().trim() };
}

/**
 * Executes a function and measures its elapsed execution time in milliseconds.
 * @param {Function} fn - Async function to execute
 * @returns {Promise<{result?: any, error?: Error, latencyMs: number}>}
 */
async function timed(fn) {
  const start = performance.now();
  try {
    const result = await fn();
    return { result, latencyMs: Math.round(performance.now() - start) };
  } catch (error) {
    return { error, latencyMs: Math.round(performance.now() - start) };
  }
}

/**
 * Runs primary and shadow ask queries in parallel with strict fault-isolation for the shadow call.
 * Shadow failures, rate limits, or timeouts never reject or block the primary return.
 * @param {Object} state - Prompt state object
 * @param {Object} questions - Questions schema object
 * @param {Object} [opts={}] - Standard ask options (env, signal, timeoutMs, fetchImpl)
 * @param {{model: string, backend: string}} [shadowConfig] - Explicit shadow configuration
 * @returns {Promise<{primary: any, shadow?: any, primaryLatencyMs: number, shadowLatencyMs?: number, shadowError?: string, primaryBackend: string, primaryModel: string, shadowBackend?: string, shadowModel?: string}>}
 */
export async function runParallelAsk(state, questions, opts = {}, shadowConfig = null) {
  const env = opts.env ?? process.env;
  const cfg = readConfig(env);
  const shadow = shadowConfig ?? resolveShadow(cfg, env);

  const primaryBackendObj = opts.backend ?? backend(env);
  const primaryKind = primaryBackendObj?.kind ?? "typesafe";
  const primaryModel = opts.model ?? env.JEV_MODEL ?? cfg.models?.[primaryKind] ?? cfg.model ?? DEFAULT_MODEL[primaryKind];

  const primaryTask = timed(() => ask(state, questions, opts));

  let shadowBackendObj = null;
  if (shadow) {
    try {
      shadowBackendObj = resolveBackend(shadow.backend, env);
    } catch {}
  }

  const shadowTimeoutMs = opts.shadowTimeoutMs ?? +(env.JEV_GUARD_SHADOW_TIMEOUT_MS || 4_000);
  const shadowAbort = new AbortController();
  const shadowSignal = opts.signal ? AbortSignal.any([opts.signal, shadowAbort.signal]) : shadowAbort.signal;

  const shadowTask = shadow
    ? timed(() => {
        if (!shadowBackendObj) {
          throw new Error(`no credentials configured for shadow backend "${shadow.backend}"`);
        }
        return ask(state, questions, {
          ...opts,
          backend: shadowBackendObj,
          model: shadow.model,
          timeoutMs: shadowTimeoutMs,
          signal: shadowSignal,
        });
      })
    : null;

  if (opts.compare) {
    const [primaryRes, shadowRes] = await Promise.all([
      primaryTask,
      shadowTask ? shadowTask : Promise.resolve(null),
    ]);
    if (primaryRes.error) throw primaryRes.error;
    return {
      primary: primaryRes.result,
      primaryLatencyMs: primaryRes.latencyMs,
      primaryBackend: primaryKind,
      primaryModel,
      shadow: shadowRes?.result,
      shadowLatencyMs: shadowRes?.latencyMs,
      shadowError: shadowRes?.error?.message,
      shadowBackend: shadow?.backend,
      shadowModel: shadow?.model,
    };
  }

  // Hook / standard mode: primary settles first so verdicts are never delayed by shadow timeouts.
  const primaryRes = await primaryTask;
  if (primaryRes.error) {
    shadowAbort.abort();
    throw primaryRes.error;
  }

  let shadowRes = null;
  if (shadowTask) {
    const remainingMs = Math.max(500, shadowTimeoutMs - primaryRes.latencyMs);
    const graceMs = opts.shadowGraceMs ?? +(env.JEV_GUARD_SHADOW_GRACE_MS || remainingMs);
    const graceTimeout = new Promise((res) =>
      setTimeout(() => res({ error: new Error("shadow timeout (grace period exceeded)"), latencyMs: shadowTimeoutMs }), graceMs)
    );
    shadowRes = await Promise.race([shadowTask, graceTimeout]);
    if (shadowRes.error && shadowRes.error.message.includes("grace period")) {
      shadowAbort.abort();
    }
  }

  return {
    primary: primaryRes.result,
    primaryLatencyMs: primaryRes.latencyMs,
    primaryBackend: primaryKind,
    primaryModel,
    shadow: shadowRes?.result,
    shadowLatencyMs: shadowRes?.latencyMs,
    shadowError: shadowRes?.error?.message,
    shadowBackend: shadow?.backend,
    shadowModel: shadow?.model,
  };
}

/**
 * Safely appends an evaluation record to the eval.jsonl telemetry log file.
 * Non-blocking, sanitized, and never throws.
 * @param {Object} record - Evaluation telemetry record
 * @param {NodeJS.ProcessEnv} [env=process.env] - Environment variables object
 */
export async function logEvalRecord(record, env = process.env) {
  try {
    const file = evalConfigFile(env);
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    const sanitized = {
      timestamp: Date.now(),
      ...record,
      preview: record.preview ? redactSecrets(record.preview) : undefined,
    };
    const line = JSON.stringify(sanitized) + "\n";
    await appendFile(file, line, { mode: 0o600 });
  } catch (err) {
    if (process.env.DEBUG) {
      console.warn(`jev-guard: failed to log eval record: ${err.message}`);
    }
  }
}

/**
 * Reads and parses evaluation records from a JSONL file, bounded to the most recent records.
 * @param {string} [file] - Path to jsonl file
 * @param {NodeJS.ProcessEnv} [env=process.env] - Environment variables object
 * @param {number} [maxRecords=10000] - Maximum records to load
 * @returns {Array<Object>} Parsed evaluation records
 */
export function readEvalRecords(file, env = process.env, maxRecords = 10_000) {
  const filePath = file ?? evalConfigFile(env);
  if (!existsSync(filePath)) return [];
  try {
    const content = readFileSync(filePath, "utf8");
    const lines = content.split("\n").map((line) => line.trim()).filter(Boolean);
    const slice = lines.length > maxRecords ? lines.slice(-maxRecords) : lines;
    return slice
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  } catch {
    return [];
  }
}

/**
 * Computes statistical percentiles (p50, p90, p95) from an array of numbers using linear interpolation.
 * @param {number[]} values - Array of numeric measurements
 * @returns {{p50: number, p90: number, p95: number, avg: number}}
 */
function percentiles(values) {
  if (!values.length) return { p50: 0, p90: 0, p95: 0, avg: 0 };
  const sorted = [...values].sort((a, b) => a - b);
  const interpolate = (pct) => {
    const rank = (sorted.length - 1) * pct;
    const lower = Math.floor(rank);
    const upper = Math.ceil(rank);
    const weight = rank - lower;
    return Math.round(sorted[lower] * (1 - weight) + sorted[upper] * weight);
  };
  const avg = Math.round(sorted.reduce((acc, v) => acc + v, 0) / sorted.length);
  return { p50: interpolate(0.5), p90: interpolate(0.9), p95: interpolate(0.95), avg };
}

/**
 * Generates an evaluation report and comparative statistics from evaluation telemetry records.
 * @param {Array<Object>} records - Array of eval telemetry records
 * @returns {Object} Comprehensive evaluation metrics
 */
export function generateEvalReport(records) {
  const total = records.length;
  if (!total) {
    return {
      total: 0,
      agreedCount: 0,
      agreementRate: 0,
      divergenceCount: 0,
      events: {},
      divergences: [],
      latency: { primary: { p50: 0, p90: 0, p95: 0, avg: 0 }, shadow: { p50: 0, p90: 0, p95: 0, avg: 0 } },
      shadowErrors: 0,
    };
  }

  let agreedCount = 0;
  let shadowErrors = 0;
  const events = { action: 0, content: 0, instruction: 0 };
  const divergences = [];
  const primaryLatencies = [];
  const shadowLatencies = [];

  for (const r of records) {
    const type = r.event ?? "action";
    events[type] = (events[type] ?? 0) + 1;

    if (r.primary?.latencyMs != null) primaryLatencies.push(r.primary.latencyMs);
    if (r.shadow?.latencyMs != null) shadowLatencies.push(r.shadow.latencyMs);

    if (r.shadow?.error) {
      shadowErrors++;
      continue;
    }

    if (r.agreed) {
      agreedCount++;
    } else {
      divergences.push(r);
    }
  }

  const evaluatedCount = total - shadowErrors;
  const agreementRate = evaluatedCount > 0 ? Number(((agreedCount / evaluatedCount) * 100).toFixed(1)) : 0;

  return {
    total,
    evaluatedCount,
    agreedCount,
    agreementRate,
    divergenceCount: divergences.length,
    shadowErrors,
    events,
    divergences,
    latency: {
      primary: percentiles(primaryLatencies),
      shadow: percentiles(shadowLatencies),
    },
  };
}
