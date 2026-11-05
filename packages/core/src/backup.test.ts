import { describe, expect, it } from "vitest";
import {
  BACKUP_PASSPHRASE_MIN,
  backupFileName,
  backupLineSchema,
  backupManifestSchema,
  passphraseProblem,
  restoreLevel,
} from "./backup.ts";

const h = (c: string) => c.repeat(64);

describe("restoreLevel", () => {
  it("accepts a backup whose migrations are the first of ours", () => {
    expect(restoreLevel([h("a"), h("b")], [h("a"), h("b"), h("c")])).toEqual({ ok: true, level: 2 });
    expect(restoreLevel([h("a")], [h("a")])).toEqual({ ok: true, level: 1 });
  });

  it("refuses a backup of a newer version or of another product", () => {
    expect(restoreLevel([h("a"), h("b")], [h("a")])).toEqual({ ok: false, reason: "newer" });
    expect(restoreLevel([h("a"), h("x")], [h("a"), h("b")])).toEqual({ ok: false, reason: "foreign" });
  });
});

describe("passphraseProblem", () => {
  it("wants at least 16 characters that are not only blanks", () => {
    expect(passphraseProblem("x".repeat(BACKUP_PASSPHRASE_MIN))).toBeNull();
    expect(passphraseProblem("x".repeat(BACKUP_PASSPHRASE_MIN - 1))).toBe("too-short");
    expect(passphraseProblem(" ".repeat(40))).toBe("too-short");
    expect(passphraseProblem("x".repeat(2000))).toBe("too-long");
  });
});

describe("the file's lines", () => {
  it("names the file by the UTC day", () => {
    expect(backupFileName(new Date("2026-11-05T23:30:00-02:00"))).toBe("garnetops-backup-2026-11-06.age");
  });

  it("accepts only table names of a fixed shape", () => {
    expect(backupLineSchema.safeParse({ kind: "table", name: "repository" }).success).toBe(true);
    expect(backupLineSchema.safeParse({ kind: "table", name: 'x"; drop table user; --' }).success).toBe(
      false,
    );
    const manifest = {
      kind: "garnetops-backup",
      format: 1,
      appVersion: "0.1.0",
      createdAt: "2026-11-05T10:00:00.000Z",
      migrations: [h("a")],
      tables: ["organization", "Bad Name"],
    };
    expect(backupManifestSchema.safeParse(manifest).success).toBe(false);
  });
});
