import { appVersionOf } from "@garnetops/core/system-status";

/**
 * Version of the running build. Release images bake it in at build time
 * (`ARG VERSION` → `APP_VERSION`), so it always names the code that runs;
 * builds without a version (development, tests) report the current 0.0.7 alpha.
 */
export const APP_VERSION = appVersionOf(process.env.APP_VERSION);
