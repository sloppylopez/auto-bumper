import { fetchWithRetry } from "../src/lib/fetch-retry.ts";

// Copied once, before other test files replace this module via mock.module.
export const realFetchWithRetry = fetchWithRetry;
