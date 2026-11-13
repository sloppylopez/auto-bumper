import { afterEach, describe, expect, test } from "bun:test";
import { createSpinner } from "../src/lib/spinner.ts";

const stdout = process.stdout as NodeJS.WriteStream & { isTTY?: boolean };
const savedWrite = process.stdout.write.bind(process.stdout);
const savedLog = console.log;
const savedError = console.error;
const savedIsTTY = stdout.isTTY;
const savedNoColor = process.env.NO_COLOR;
const savedForce = process.env.FORCE_COLOR;
const savedTerm = process.env.TERM;

function capture(): string[] {
  const chunks: string[] = [];
  process.stdout.write = ((chunk: unknown) => {
    chunks.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;
  return chunks;
}

afterEach(() => {
  process.stdout.write = savedWrite;
  console.log = savedLog;
  console.error = savedError;
  stdout.isTTY = savedIsTTY;
  if (savedNoColor === undefined) delete process.env.NO_COLOR;
  else process.env.NO_COLOR = savedNoColor;
  if (savedForce === undefined) delete process.env.FORCE_COLOR;
  else process.env.FORCE_COLOR = savedForce;
  if (savedTerm === undefined) delete process.env.TERM;
  else process.env.TERM = savedTerm;
});

describe("hourglass", () => {
  test("flips in place on a terminal", () => {
    delete process.env.NO_COLOR;
    delete process.env.FORCE_COLOR;
    delete process.env.TERM;
    stdout.isTTY = true;
    const chunks = capture();
    let tick: (() => void) | undefined;
    const origInterval = globalThis.setInterval;
    const origClear = globalThis.clearInterval;
    globalThis.setInterval = ((fn: TimerHandler, ms?: number) => {
      expect(ms).toBe(500);
      tick = fn as () => void;
      return 1 as unknown as ReturnType<typeof setInterval>;
    }) as typeof setInterval;
    const cleared: unknown[] = [];
    globalThis.clearInterval = ((id: unknown) => {
      cleared.push(id);
    }) as typeof clearInterval;
    try {
      const spinner = createSpinner("wait").start();
      expect(chunks.join("")).toContain("\r\u001b[K\u23f3 wait");
      tick?.();
      expect(chunks.join("")).toContain("\r\u001b[K\u231b wait");
      spinner.text = "next";
      const beforeStop = chunks.join("");
      expect(beforeStop).not.toContain("\n");
      expect(beforeStop).toContain("\r\u001b[K\u231b next");
      spinner.stop();
      expect(cleared.length).toBeGreaterThan(0);
      expect(console.log).toBe(savedLog);
    } finally {
      globalThis.setInterval = origInterval;
      globalThis.clearInterval = origClear;
    }
  });

  test("a log finishes the live line before printing", () => {
    delete process.env.NO_COLOR;
    delete process.env.FORCE_COLOR;
    delete process.env.TERM;
    stdout.isTTY = true;
    const lines: string[] = [];
    console.log = ((msg?: unknown) => {
      lines.push(String(msg));
    }) as typeof console.log;
    const chunks = capture();
    const origInterval = globalThis.setInterval;
    const origClear = globalThis.clearInterval;
    globalThis.setInterval = (() => 1 as unknown as ReturnType<typeof setInterval>) as typeof setInterval;
    globalThis.clearInterval = (() => {}) as typeof clearInterval;
    try {
      createSpinner("wait").start();
      console.log("side");
      const joined = chunks.join("");
      expect(joined).toContain("\u23f3");
      expect(joined.indexOf("\n")).toBeGreaterThan(joined.indexOf("\u23f3"));
      expect(lines).toEqual(["side"]);
    } finally {
      globalThis.setInterval = origInterval;
      globalThis.clearInterval = origClear;
    }
  });

  test("piped output stays a static hourglass", () => {
    stdout.isTTY = false;
    const lines: string[] = [];
    console.log = ((msg?: unknown) => {
      lines.push(String(msg));
    }) as typeof console.log;
    const spinner = createSpinner("wait").start();
    spinner.text = "wait";
    spinner.stop();
    expect(lines).toEqual(["\u23f3 wait"]);
  });

  test("NO_COLOR still flips on a terminal", () => {
    process.env.NO_COLOR = "1";
    delete process.env.FORCE_COLOR;
    delete process.env.TERM;
    stdout.isTTY = true;
    const chunks = capture();
    const origInterval = globalThis.setInterval;
    const origClear = globalThis.clearInterval;
    globalThis.setInterval = (() => 1 as unknown as ReturnType<typeof setInterval>) as typeof setInterval;
    globalThis.clearInterval = (() => {}) as typeof clearInterval;
    try {
      const spinner = createSpinner("wait").start();
      expect(chunks.join("")).toContain("\r\u001b[K\u23f3 wait");
      spinner.stop();
    } finally {
      globalThis.setInterval = origInterval;
      globalThis.clearInterval = origClear;
    }
  });
});
