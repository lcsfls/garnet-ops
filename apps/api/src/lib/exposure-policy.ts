/**
 * The address policy of the exposure API (ADR 0023). Production accepts public addresses only. Tests may open the documentation
 * ranges and loopback by setting `exposurePolicy.allowTestRanges`; the hook is ignored outside `NODE_ENV=test`, so no configuration
 * and no request can switch it on in a running installation.
 */
export const exposurePolicy = { allowTestRanges: false };

/** Whether the test hook is in force: set, and only while running under the test runner. */
export const allowTestRanges = (): boolean =>
  exposurePolicy.allowTestRanges && process.env.NODE_ENV === "test";
