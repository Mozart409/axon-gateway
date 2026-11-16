import fc from "fast-check";
import type { Viewport } from "./types";

export const BREAKPOINTS: Viewport[] = [
  { width: 320, height: 640 },
  { width: 390, height: 844 },
  { width: 768, height: 1024 },
  { width: 1024, height: 768 },
  { width: 1280, height: 800 },
  { width: 1920, height: 1080 },
  { width: 2560, height: 1440 },
  { width: 3840, height: 2160 },
];

export const viewportArb = fc.record({
  width: fc.integer({ min: 320, max: 3840 }),
  height: fc.integer({ min: 480, max: 2160 }),
});

export function themeArb(ids: string[]) {
  return fc.constantFrom(...ids);
}

/**
 * Shared fast-check parameters. A failing run prints its seed and path; rerun
 * with `E2E_SEED=<seed>` to reproduce it. `E2E_RUNS` sets the run count.
 */
export function fcParams(): fc.Parameters<unknown> {
  return {
    numRuns: Number(process.env.E2E_RUNS ?? 4),
    seed: process.env.E2E_SEED ? Number(process.env.E2E_SEED) : undefined,
    verbose: fc.VerbosityLevel.Verbose,
    endOnFailure: true,
  };
}
