export interface Spinner {
  text: string;
  start(): this;
  stop(): this;
  succeed(text?: string): this;
  fail(text?: string): this;
  warn(text?: string): this;
}

export type SpinnerFactory = (text: string) => Spinner;

/** ⏳ then ⌛. A terminal cannot rotate one glyph, so the live line flips. */
const HOURGLASS = ["\u23f3", "\u231b"];
const FLIP_MS = 500;

/** Piped logs and dumb terminals stay a single static hourglass. NO_COLOR only strips color. */
function hourglassFlips(): boolean {
  if (process.env.TERM === "dumb") return false;
  return Boolean(process.stdout.isTTY);
}

/** Progress/success lines go to stdout; warnings and failures go to stderr, so red (stderr) stays reserved for real problems. */
class EmojiStatus implements Spinner {
  private label: string;
  private last = "";
  private timer: ReturnType<typeof setInterval> | null = null;
  private frame = 0;
  /** True while the current hourglass line has no newline yet. */
  private live = false;
  private liveLabel: string | null = null;
  private armed = false;
  private savedLog: typeof console.log = console.log;
  private savedError: typeof console.error = console.error;

  constructor(text: string) {
    this.label = text;
  }

  get text(): string {
    return this.label;
  }

  set text(value: string) {
    this.label = value;
    this.showHourglass();
  }

  start(): this {
    this.showHourglass();
    return this;
  }

  stop(): this {
    this.commitLiveLine();
    return this;
  }

  succeed(text?: string): this {
    this.commitLiveLine();
    return this.say("\u2705", text);
  }

  fail(text?: string): this {
    this.commitLiveLine();
    return this.say("\u274c", text, true);
  }

  warn(text?: string): this {
    this.commitLiveLine();
    // Two spaces: a Windows console eats the single gap after this emoji, so the count sticks to the triangle.
    return this.say("\u26a0\ufe0f ", text, true);
  }

  private showHourglass(): void {
    if (!hourglassFlips()) {
      this.commitLiveLine();
      this.say("\u23f3", this.label);
      return;
    }
    if (this.live && this.liveLabel === this.label) return;
    // A new count rewrites this line. A newline here froze every finished line on the first frame.
    this.liveLabel = this.label;
    if (this.timer !== null) {
      this.paintFrame();
      return;
    }
    this.frame = 0;
    this.paintFrame();
    this.arm();
    const timer = setInterval(() => {
      this.frame = (this.frame + 1) % HOURGLASS.length;
      this.paintFrame();
    }, FLIP_MS);
    this.timer = timer;
    if (typeof timer === "object" && timer !== null && "unref" in timer) {
      (timer as { unref: () => void }).unref();
    }
  }

  private paintFrame(): void {
    const mark = HOURGLASS[this.frame] ?? HOURGLASS[0];
    // Erase to end of line so a shorter label, or a narrower glyph, does not leave crumbs.
    process.stdout.write(`\r\u001b[K${mark} ${this.label}`);
    this.live = true;
    this.last = `${mark} ${this.label}`;
  }

  /** End the live line so the next status, or any other log, starts on its own line. */
  private commitLiveLine(): void {
    this.clearTimer();
    const wasLive = this.live;
    this.live = false;
    this.liveLabel = null;
    this.disarm();
    if (wasLive) process.stdout.write("\n");
  }

  /** Other console output must finish the live line first, or it glues onto the hourglass. */
  private arm(): void {
    if (this.armed) return;
    this.armed = true;
    this.savedLog = console.log;
    this.savedError = console.error;
    const log = this.savedLog.bind(console);
    const error = this.savedError.bind(console);
    console.log = ((...args: Parameters<typeof console.log>) => {
      this.commitLiveLine();
      log(...args);
    }) as typeof console.log;
    console.error = ((...args: Parameters<typeof console.error>) => {
      this.commitLiveLine();
      error(...args);
    }) as typeof console.error;
  }

  private disarm(): void {
    if (!this.armed) return;
    console.log = this.savedLog;
    console.error = this.savedError;
    this.armed = false;
  }

  private clearTimer(): void {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private say(mark: string, text: string | undefined, toStderr = false): this {
    if (text !== undefined) this.label = text;
    const line = `${mark} ${this.label}`;
    if (line === this.last) return this;
    this.last = line;
    if (toStderr) console.error(line);
    else console.log(line);
    return this;
  }
}

export function createSpinner(text: string): Spinner {
  return new EmojiStatus(text);
}

export const defaultSpinnerFactory: SpinnerFactory = (text: string) => createSpinner(text);
