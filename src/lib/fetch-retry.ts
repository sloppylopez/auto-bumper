/**
 * Fetch with exponential backoff for transient HTTP / network failures.
 */

export interface FetchRetryOptions {
  retries?: number;
  baseDelayMs?: number;
  /** HTTP statuses that should retry (default: 408, 429, 500, 502, 503, 504). */
  retryStatuses?: number[];
  /** Optional label for error messages. */
  label?: string;
}

const DEFAULT_RETRY_STATUSES = new Set([408, 429, 500, 502, 503, 504]);

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export async function fetchWithRetry(
  input: string | URL,
  init?: RequestInit,
  opts: FetchRetryOptions = {},
): Promise<Response> {
  const retries = opts.retries ?? 3;
  const baseDelayMs = opts.baseDelayMs ?? 400;
  const retryStatuses = opts.retryStatuses
    ? new Set(opts.retryStatuses)
    : DEFAULT_RETRY_STATUSES;
  const label = opts.label || String(input);

  let lastErr: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const resp = await fetch(input, init);
      if (resp.ok || !retryStatuses.has(resp.status) || attempt === retries) {
        return resp;
      }
      lastErr = new Error(`${label}: HTTP ${resp.status}`);
      // Honor Retry-After when present (seconds).
      const retryAfter = resp.headers.get("retry-after");
      const waitMs = retryAfter && /^\d+$/.test(retryAfter)
        ? Number(retryAfter) * 1000
        : baseDelayMs * 2 ** attempt;
      await sleep(waitMs);
    } catch (err) {
      lastErr = err;
      if (attempt === retries) break;
      await sleep(baseDelayMs * 2 ** attempt);
    }
  }

  const msg = lastErr instanceof Error ? lastErr.message : String(lastErr);
  throw new Error(`${label}: exhausted retries — ${msg}`);
}
