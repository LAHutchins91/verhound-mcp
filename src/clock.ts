let override: (() => number) | null = null;

export function nowMs(): number {
  return override ? override() : Date.now();
}

export function nowDate(): Date {
  return new Date(nowMs());
}

export function setClockForTests(ms: number | null): void {
  override = ms === null ? null : () => ms;
}
