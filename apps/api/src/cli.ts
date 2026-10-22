/**
 * Operator commands, run inside the API container (ADR 0017):
 *
 *   node apps/api/src/cli.ts reset-second-factor <email> [--yes]
 *
 * The only authority is a shell in the container, the same trust as access to the database.
 * Nothing here is reachable over the network.
 */
import { pool } from "./db.ts";
import { inspectSecondFactor, resetSecondFactor } from "./lib/second-factor-reset.ts";

const USAGE = `Usage:
  node apps/api/src/cli.ts reset-second-factor <email> [--yes]

reset-second-factor removes the authenticator app and all passkeys of one account and ends its
sessions. The password stays. At the next sign-in the person sets up a new second factor.
Without --yes the command only shows what it would do.`;

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  if (command !== "reset-second-factor") {
    console.error(USAGE);
    return command === undefined || command === "help" || command === "--help" ? 0 : 2;
  }
  const confirmed = rest.includes("--yes");
  const email = rest.find((arg) => !arg.startsWith("--"));
  if (!email) {
    console.error(USAGE);
    return 2;
  }
  const summary = await inspectSecondFactor(email);
  if (!summary) {
    console.error("No account with this address.");
    return 1;
  }
  console.log(`Account: ${summary.name} <${summary.email}>`);
  console.log(`Authenticator app: ${summary.totpEnrolled ? "enrolled, will be removed" : "none"}`);
  console.log(`Passkeys: ${summary.passkeys}${summary.passkeys > 0 ? ", will be removed" : ""}`);
  console.log(`Signed-in sessions: ${summary.sessions}, will be ended`);
  if (!confirmed) {
    console.log("Nothing changed. Run again with --yes to do it.");
    return 0;
  }
  await resetSecondFactor(summary);
  console.log("Done. The next sign-in with the password leads to the setup of a new second factor.");
  return 0;
}

let code = 1;
try {
  code = await main(process.argv.slice(2));
} catch (error) {
  // The message only: connection strings and queries can carry secrets.
  console.error(`cli: ${error instanceof Error ? error.message : "failed"}`);
} finally {
  await pool.end().catch(() => {});
}
process.exit(code);
