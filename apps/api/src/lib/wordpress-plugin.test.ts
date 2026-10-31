import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { wordpressPluginZip } from "./wordpress-plugin.ts";

let python = true;
try {
  execFileSync("python3", ["--version"], { stdio: "ignore" });
} catch {
  python = false;
}

describe("the WordPress plugin zip (ADR 0042, part 4)", () => {
  it.skipIf(!python)(
    "is a valid zip of the plugin folder with its version, the same every time",
    async () => {
      // The installation's folder is missing in a checkout, so the repository's plugin is served.
      const first = await wordpressPluginZip("/nonexistent/wordpress-plugin");
      expect(first).not.toBeNull();
      expect(first?.version).toMatch(/^\d+\.\d+\.\d+$/);
      const dir = mkdtempSync(join(tmpdir(), "garnetops-zip-"));
      try {
        const file = join(dir, "plugin.zip");
        writeFileSync(file, first?.zip as Buffer);
        const listing = execFileSync(
          "python3",
          [
            "-I",
            "-c",
            "import sys,zipfile;z=zipfile.ZipFile(sys.argv[1]);assert z.testzip() is None;print('\\n'.join(z.namelist()))",
            file,
          ],
          { encoding: "utf8" },
        );
        expect(listing.trim().split("\n")).toEqual(
          expect.arrayContaining([
            "garnetops/garnetops.php",
            "garnetops/LICENSE",
            "garnetops/includes/class-garnetops-access.php",
            "garnetops/includes/class-garnetops-inventory.php",
          ]),
        );
        expect(listing).not.toContain("tests/");
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
      expect((await wordpressPluginZip("/nonexistent/wordpress-plugin"))?.sha256).toBe(first?.sha256);
    },
  );
});
