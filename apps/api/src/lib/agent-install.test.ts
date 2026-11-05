import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { installScript, SANDBOX_CHECK, SYSTEMD_UNIT } from "./agent-install.ts";

const script = installScript("https://garnetops.example.test", { amd64: "a".repeat(64) });

describe("the install script of the systemd agent", () => {
  it("is valid POSIX shell", () => {
    const check = spawnSync("sh", ["-n"], { input: script, encoding: "utf8" });
    expect(check.status, check.stderr).toBe(0);
  });

  it("tries exactly the unit's own sandbox settings in a container, never weaker ones", () => {
    const unit = new Set(SYSTEMD_UNIT.split("\n"));
    for (const setting of SANDBOX_CHECK) expect(unit).toContain(setting);
    expect(script).toContain("systemd-detect-virt --container");
    expect(script).toContain("/run/systemd/container");
    expect(script).toContain(
      `systemd-run --wait --quiet --collect ${SANDBOX_CHECK.map((p) => `-p ${p}`).join(" ")} /bin/true`,
    );
    expect(script).toContain("enable Options > Features > Nesting");
    // The check runs before anything is downloaded or installed.
    expect(script.indexOf("systemd-run --wait")).toBeLessThan(script.indexOf("TMP=$(mktemp -d)"));
    expect(script.indexOf("systemd-run --wait")).toBeLessThan(script.indexOf("useradd"));
  });

  describe("run with stand-in commands", () => {
    let dir = "";
    beforeAll(async () => {
      dir = await mkdtemp(join(tmpdir(), "garnetops-install-"));
      const stub = async (name: string, body: string) => {
        await writeFile(join(dir, name), `#!/bin/sh\n${body}\n`);
        await chmod(join(dir, name), 0o755);
      };
      await stub("id", "echo 0");
      await stub("systemctl", "exit 0");
      await stub("systemd-detect-virt", "echo lxc");
      // An unprivileged container without nesting: the transient service fails with 226/NAMESPACE.
      await stub("systemd-run", "exit 1");
      await writeFile(join(dir, "install.sh"), script);
    });
    afterAll(async () => {
      await rm(dir, { recursive: true, force: true });
    });
    const run = (path: string) =>
      spawnSync("/bin/sh", [join(dir, "install.sh")], {
        env: { PATH: path, GARNETOPS_ENROLMENT_CODE: `goe_${"a".repeat(43)}` },
        encoding: "utf8",
      });

    it("names the next step when systemd is missing (e.g. Alpine with OpenRC)", async () => {
      const empty = await mkdtemp(join(tmpdir(), "garnetops-install-empty-"));
      await writeFile(join(empty, "id"), "#!/bin/sh\necho 0\n");
      await chmod(join(empty, "id"), 0o755);
      const result = run(empty);
      await rm(empty, { recursive: true, force: true });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("systemd is needed");
      expect(result.stderr).toContain("OpenRC");
      expect(result.stderr).toContain("Debian or Ubuntu");
    });

    it("stops in a container whose systemd cannot set up the sandbox, before installing anything", () => {
      const result = run(dir);
      expect(result.status).toBe(1);
      if (existsSync("/run/systemd/system")) {
        expect(result.stderr).toContain("this is a container (lxc)");
        expect(result.stderr).toContain("Nesting");
      } else {
        // This machine does not run systemd itself: the script stops one step earlier.
        expect(result.stderr).toContain("systemd is needed");
      }
    });
  });
});
