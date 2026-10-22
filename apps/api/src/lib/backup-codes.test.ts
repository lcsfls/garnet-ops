import { describe, expect, it } from "vitest";
import { BACKUP_CODE_COUNT, newBackupCodes, openBackupCodes, sealBackupCodes } from "./backup-codes.ts";

const KEY = "test-secret-with-at-least-32-characters-0000";

describe("backup codes", () => {
  it("makes ten distinct codes in the format the sign-in reads", () => {
    const codes = newBackupCodes();
    expect(codes).toHaveLength(BACKUP_CODE_COUNT);
    expect(new Set(codes).size).toBe(BACKUP_CODE_COUNT);
    for (const code of codes) expect(code).toMatch(/^[A-Za-z0-9]{5}-[A-Za-z0-9]{5}$/);
  });

  it("stores them encrypted and reads them back", async () => {
    const codes = newBackupCodes();
    const sealed = await sealBackupCodes(codes, KEY);
    expect(sealed).not.toContain(codes[0]);
    expect(await openBackupCodes(sealed, KEY)).toEqual(codes);
  });

  it("does not open them with another key or from a damaged value", async () => {
    const sealed = await sealBackupCodes(newBackupCodes(), KEY);
    expect(await openBackupCodes(sealed, "another-secret-with-at-least-32-chars-1")).toBeNull();
    expect(await openBackupCodes("not-a-sealed-value", KEY)).toBeNull();
  });
});
