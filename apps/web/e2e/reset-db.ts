/** Drops and recreates the end-to-end database, so every run starts at first-run setup. */
import { createRequire } from "node:module";
import { E2E } from "./env.ts";

const require = createRequire(new URL("../../../packages/db/package.json", import.meta.url));
// The pg driver comes from packages/db; only the few calls used here are typed.
const pg = require("pg") as {
  Client: new (options: {
    connectionString: string;
  }) => {
    connect(): Promise<void>;
    query(sql: string): Promise<unknown>;
    end(): Promise<void>;
  };
};

const client = new pg.Client({ connectionString: E2E.adminDatabaseUrl });
await client.connect();
try {
  await client.query("drop database if exists garnetops_e2e with (force)");
  await client.query("create database garnetops_e2e");
} finally {
  await client.end();
}
console.log("e2e: fresh database garnetops_e2e");
