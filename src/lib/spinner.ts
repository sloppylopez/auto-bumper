export interface Spinner {
  text: string;
  start(): this;
  stop(): this;
  succeed(text?: string): this;
  fail(text?: string): this;
  warn(text?: string): this;
}

export type SpinnerFactory = (text: string) => Spinner;

/** Progress/success lines go to stdout; warnings and failures go to stderr, so red (stderr) stays reserved for real problems. */
class EmojiStatus implements Spinner {
  private label: string;
  private last = "";

  constructor(text: string) {
    this.label = text;
  }

  get text(): string {
    return this.label;
  }

  set text(value: string) {
    this.label = value;
    this.say("\u23f3", value);
  }

  start(): this {
    this.say("\u23f3", this.label);
    return this;
  }

  stop(): this {
    return this;
  }

  succeed(text?: string): this {
    return this.say("\u2705", text);
  }

  fail(text?: string): this {
    return this.say("\u274c", text, true);
  }

  warn(text?: string): this {
    return this.say("\u26a0\ufe0f", text, true);
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
