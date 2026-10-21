import { createHmac } from "node:crypto";
import type { Page } from "@playwright/test";

export const OWNER = {
  organization: "E2E Org",
  name: "Erika Owner",
  email: "owner@e2e.test",
  password: "e2e-password-long-enough",
};

export const STATE_FILE = "e2e/.state/owner.json";

function base32Decode(input: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of input.replace(/=+$/, "").toUpperCase()) {
    bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(Number.parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

/** RFC 6238 TOTP (SHA-1, 6 digits, 30 s), as an authenticator app computes it. */
export function totp(secret: string, at = Date.now()): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)));
  const hmac = createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = (hmac[hmac.length - 1] ?? 0) & 15;
  return String((hmac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

/** Waits until a new 30-second TOTP period starts, so a fresh code is never a replay of the last one. */
export async function nextTotpPeriod(page: Page): Promise<void> {
  await page.waitForTimeout(30_000 - (Date.now() % 30_000) + 250);
}

/** Opens the account panel behind the avatar in the top bar. */
export async function openAccountMenu(page: Page): Promise<void> {
  await page.getByRole("button", { name: /^Account: / }).click();
}

export async function signOut(page: Page): Promise<void> {
  await openAccountMenu(page);
  await page.getByRole("button", { name: "Sign out" }).click();
}

/** Collects CSP violations, uncaught errors and console errors, so tests can assert there are none. */
export function watchForProblems(page: Page): string[] {
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(`pageerror: ${error.message}`));
  page.on("console", (message) => {
    // Expected 4xx answers (wrong code, wrong token) are logged by the browser as failed resources.
    if (message.type() === "error" && !/Failed to load resource/.test(message.text())) {
      problems.push(`console: ${message.text()}`);
    }
  });
  return problems;
}

/**
 * Content that sticks out of its card (a table wider than its card, a cut-off
 * button) is listed by the card's heading or first text, so a failure names it.
 */
export async function overflowingCards(page: Page): Promise<string[]> {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll("main section"))
      .filter((card) => card.scrollWidth > card.clientWidth + 1)
      .map((card) => (card.textContent ?? "").trim().slice(0, 60)),
  );
}

/** The page is usable without horizontal scrolling (AGENTS.md rule 5). */
export async function hasNoHorizontalScroll(page: Page): Promise<boolean> {
  return page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);
}
