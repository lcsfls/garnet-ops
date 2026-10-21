/**
 * Version of the running build. Release images bake it in at build time
 * (`ARG VERSION` → `APP_VERSION`), so it always names the code that runs;
 * development and test builds report `0.0.0-dev`.
 */
export const APP_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(process.env.APP_VERSION ?? "")
  ? (process.env.APP_VERSION as string)
  : "0.0.0-dev";
