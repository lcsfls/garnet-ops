import { createUpdaterClient } from "@restow-backup/cicd-updater";
import { env } from "../env.ts";

/**
 * The API's one client for the optional update sidecar (cicd-updater, ADR 0007).
 *
 * The sidecar is opt-in. With UPDATER_URL empty, or without the token file (the
 * `updater` Compose profile is not running), `state()` resolves to null and every other
 * method throws `UpdaterUnavailableError`: GarnetOps keeps working and the Updates page
 * shows the manual steps. Only the API holds the token; the worker never does.
 */
export const updater = createUpdaterClient({
  url: env.UPDATER_URL,
  tokenFile: env.UPDATER_TOKEN_FILE,
});
