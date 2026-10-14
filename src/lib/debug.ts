import { LOG_PREFIX } from "./brand.ts";

/**
 * Lightweight debug logger — only emits when AUTO_BUMPER_DEBUG is set.
 */
export function debug(...args: unknown[]): void {
  if (process.env.AUTO_BUMPER_DEBUG) {
    console.log(LOG_PREFIX, ...args);
  }
}
