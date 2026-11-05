import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { installScript, OPENRC_LOG, OPENRC_SERVICE, SANDBOX_CHECK, SYSTEMD_UNIT } from "./agent-install.ts";

const script = installScript("https://garnetops.example.test", { amd64: "a".repeat(64) });
const CODE = `goe_${"a".repeat(43)}`;

async function stub(dir: string, name: string, body: string) {
  await writeFile(join(dir, name), `#!/bin/sh\n${body}\n`);
  await chmod(join(dir, name), 0o755);
}

describe("the install script of the host agent", () => {
  it("is valid POSIX shell, and so is the OpenRC service it writes", () => {
    for (const text of [script, OPENRC_SERVICE]) {
      const check = spawnSync("sh", ["-n"], { input: text, encoding: "utf8" });
      expect(check.status, check.stderr).toBe(0);
    }
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

  it("keeps the systemd unit as hardened as before", () => {
    for (const line of [
      "NoNewPrivileges=yes",
      "CapabilityBoundingSet=",
      "ProtectSystem=strict",
      "MemoryDenyWriteExecute=yes",
      "SystemCallFilter=~@privileged @resources",
      "MemoryMax=256M",
      "CPUQuota=20%",
      "User=garnetops-agent",
    ]) {
      expect(SYSTEMD_UNIT.split("\n")).toContain(line);
    }
  });

  it("runs the OpenRC service unprivileged under supervise-daemon, restarted on failure", () => {
    const lines = OPENRC_SERVICE.split("\n");
    expect(lines[0]).toBe("#!/sbin/openrc-run");
    for (const line of [
      'supervisor="supervise-daemon"',
      'command="/usr/local/bin/garnetops-agent"',
      'command_args="run"',
      'command_user="garnetops-agent:garnetops-agent"',
      `pidfile="/run/\${RC_SVCNAME}.pid"`,
      'umask="077"',
      'no_new_privs="yes"',
      "respawn_delay=60",
      "respawn_max=0",
      `output_log="${OPENRC_LOG}"`,
      'rc_cgroup_settings="memory.max 268435456',
      'cpu.max 20000 100000"',
      "\texport GOMEMLIMIT=200MiB",
      "\texport GARNETOPS_STATE_DIR=/var/lib/garnetops-agent",
    ]) {
      expect(lines).toContain(line);
    }
    // The environment file is never sourced as shell.
    expect(OPENRC_SERVICE).not.toMatch(/^\s*\.\s/m);
    expect(OPENRC_SERVICE).not.toContain("source ");
    expect(OPENRC_SERVICE).not.toMatch(/command_user="root/);
    expect(script).toContain(OPENRC_SERVICE);
    expect(script).toContain("rc-update add garnetops-agent default");
    expect(script).toContain("adduser -S -D -H -h /nonexistent");
  });

  it("loads only the agent's own settings from the environment file, without evaluating them", async () => {
    const dir = await mkdtemp(join(tmpdir(), "garnetops-openrc-env-"));
    try {
      const envFile = join(dir, "agent.env");
      await writeFile(
        envFile,
        [
          "GARNETOPS_URL=https://garnetops.example.test",
          `GARNETOPS_ENROLMENT_CODE=${CODE}`,
          `GARNETOPS_HOST_NAME=web 01 $(touch ${join(dir, "pwned")}) \`id\``,
          "PATH=/nonexistent",
          "LD_PRELOAD=/tmp/evil.so",
          "",
        ].join("\n"),
      );
      const service = OPENRC_SERVICE.replaceAll("/etc/garnetops-agent/agent.env", envFile);
      const run = spawnSync(
        "/bin/sh",
        [
          "-c",
          `${service}\ncheckpath() { :; }\neerror() { echo "$*" >&2; }\nstart_pre || exit 9\nenv | grep -E '^(GARNETOPS_|GOMEMLIMIT|LD_PRELOAD|PATH=)' | sort`,
        ],
        { encoding: "utf8", env: { PATH: process.env.PATH ?? "/usr/bin:/bin" } },
      );
      expect(run.status, run.stderr).toBe(0);
      expect(run.stdout.trim().split("\n")).toEqual([
        `GARNETOPS_ENROLMENT_CODE=${CODE}`,
        `GARNETOPS_HOST_NAME=web 01 $(touch ${join(dir, "pwned")}) \`id\``,
        "GARNETOPS_STATE_DIR=/var/lib/garnetops-agent",
        "GARNETOPS_URL=https://garnetops.example.test",
        "GOMEMLIMIT=200MiB",
        `PATH=${process.env.PATH ?? "/usr/bin:/bin"}`,
      ]);
      expect(existsSync(join(dir, "pwned"))).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  describe("run with stand-in commands", () => {
    let dir = "";
    beforeAll(async () => {
      dir = await mkdtemp(join(tmpdir(), "garnetops-install-"));
      await stub(dir, "id", "echo 0");
      await stub(dir, "systemctl", "exit 0");
      await stub(dir, "systemd-detect-virt", "echo lxc");
      // An unprivileged container without nesting: the transient service fails with 226/NAMESPACE.
      await stub(dir, "systemd-run", "exit 1");
      await writeFile(join(dir, "install.sh"), script);
    });
    afterAll(async () => {
      await rm(dir, { recursive: true, force: true });
    });
    const run = (path: string) =>
      spawnSync("/bin/sh", [join(dir, "install.sh")], {
        env: { PATH: path, GARNETOPS_ENROLMENT_CODE: CODE },
        encoding: "utf8",
      });

    it("names the next step when neither systemd nor OpenRC runs", async () => {
      const empty = await mkdtemp(join(tmpdir(), "garnetops-install-empty-"));
      await stub(empty, "id", "echo 0");
      const result = run(empty);
      await rm(empty, { recursive: true, force: true });
      if (existsSync("/run/systemd/system") || existsSync("/sbin/openrc-run") || existsSync("/sbin/openrc"))
        return;
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("neither systemd nor OpenRC runs on this system");
      expect(result.stderr).toContain("container agent");
    });

    it("refuses an OpenRC that is installed but not running", async () => {
      if (existsSync("/run/openrc") || existsSync("/run/systemd/system")) return;
      const openrc = await mkdtemp(join(tmpdir(), "garnetops-install-openrc-"));
      await stub(openrc, "id", "echo 0");
      await stub(openrc, "openrc-run", "exit 0");
      const result = run(openrc);
      await rm(openrc, { recursive: true, force: true });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("OpenRC is installed but does not run");
    });

    it("stops in a container whose systemd cannot set up the sandbox, before installing anything", () => {
      const result = run(dir);
      expect(result.status).toBe(1);
      if (existsSync("/run/systemd/system")) {
        expect(result.stderr).toContain("this is a container (lxc)");
        expect(result.stderr).toContain("Nesting");
      } else {
        // This machine does not run systemd itself: the script stops one step earlier.
        expect(result.stderr).toMatch(/neither systemd nor OpenRC|OpenRC is installed but does not run/);
      }
    });
  });

  /**
   * The whole OpenRC path on an Alpine-like system, with BusyBox-style tools standing in: the system paths of the script are moved
   * into a temporary directory, and every command that would change the system only writes what it was asked to a log.
   */
  describe("installs on OpenRC with BusyBox tools (stand-ins)", () => {
    let dir = "";
    const agentBytes = "stand-in for the agent binary";
    const sum = createHash("sha256").update(agentBytes).digest("hex");
    const moved = (text: string) =>
      text
        .replaceAll("/run/openrc", `${dir}/run/openrc`)
        .replaceAll("/etc/init.d/", `${dir}/init.d/`)
        .replaceAll("/etc/garnetops-agent", `${dir}/etc`)
        .replaceAll("/usr/local/bin/garnetops-agent", `${dir}/bin/garnetops-agent`)
        .replaceAll("/var/lib/garnetops-agent", `${dir}/state`)
        .replaceAll("[ -d /run/systemd/system ]", "false");
    beforeAll(async () => {
      dir = await mkdtemp(join(tmpdir(), "garnetops-install-alpine-"));
      const stubs = join(dir, "stubs");
      for (const sub of ["stubs", "run/openrc", "init.d", "bin", "etc"])
        await mkdir(join(dir, sub), { recursive: true });
      const log = `echo "$(basename "$0") $*" >> ${dir}/calls.log`;
      // `id garnetops-agent` fails: the user does not exist yet.
      await stub(stubs, "id", `if [ "$1" = -u ]; then echo 0; else exit 1; fi`);
      await stub(stubs, "uname", "echo x86_64");
      await stub(stubs, "openrc-run", "exit 0");
      for (const name of ["addgroup", "adduser", "chown", "rc-update", "rc-service"])
        await stub(stubs, name, log);
      // BusyBox install: log it, and copy the file when it is not a directory.
      await stub(
        stubs,
        "install",
        `${log}\n[ "$1" = -d ] && exit 0\neval "dst=\\\${$#}"; eval "src=\\\${$(($# - 1))}"; cp "$src" "$dst"`,
      );
      // BusyBox wget: no --https-only in its help; -q -O FILE URL.
      await stub(
        stubs,
        "wget",
        `if [ "$1" = --help ]; then echo "Usage: wget [-cqS] [--spider] [-O FILE] [--no-check-certificate] URL"; exit 0; fi\n${log}\nprintf '%s' '${agentBytes}' > "$3"`,
      );
      for (const tool of ["cat", "mktemp", "rm", "head", "grep", "sha256sum", "chmod", "cp", "basename"]) {
        await symlink(`/usr/bin/${tool}`, join(stubs, tool));
      }
    });
    afterAll(async () => {
      await rm(dir, { recursive: true, force: true });
    });
    const runAlpine = async (text: string, extra: Record<string, string> = {}) => {
      await writeFile(join(dir, "install.sh"), moved(text));
      return spawnSync("/bin/sh", [join(dir, "install.sh")], {
        env: { PATH: join(dir, "stubs"), GARNETOPS_ENROLMENT_CODE: CODE, ...extra },
        encoding: "utf8",
      });
    };

    it("creates the user with BusyBox's tools, writes the service and the environment, and starts it", async () => {
      const result = await runAlpine(installScript("https://garnetops.example.test/", { amd64: sum }), {
        GARNETOPS_HOST_NAME: "alpine-01.example.lan",
      });
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toContain("installed and started as an OpenRC service");
      const calls = (await readFile(join(dir, "calls.log"), "utf8")).trim().split("\n");
      expect(calls.find((c) => c.startsWith("wget"))).toMatch(
        /^wget -q -O \S+\/agent https:\/\/garnetops\.example\.test\/api\/v1\/agent\/download\/linux-amd64$/,
      );
      expect(calls).toContain("addgroup -S garnetops-agent");
      expect(calls.find((c) => c.startsWith("adduser"))).toMatch(
        /^adduser -S -D -H -h \/nonexistent -s \/(usr\/)?sbin\/nologin -G garnetops-agent garnetops-agent$/,
      );
      expect(calls).toContain(`install -d -o garnetops-agent -g garnetops-agent -m 0700 ${dir}/state`);
      expect(calls).toContain("rc-update add garnetops-agent default");
      expect(calls).toContain("rc-service garnetops-agent restart");
      // Nothing of systemd is touched on an OpenRC host.
      expect(calls.some((c) => c.startsWith("systemctl"))).toBe(false);
      expect(await readFile(join(dir, "bin/garnetops-agent"), "utf8")).toBe(agentBytes);
      expect(await readFile(join(dir, "init.d/garnetops-agent"), "utf8")).toBe(moved(OPENRC_SERVICE));
      expect((await readFile(join(dir, "etc/agent.env"), "utf8")).split("\n")).toEqual([
        "GARNETOPS_URL=https://garnetops.example.test",
        `GARNETOPS_ENROLMENT_CODE=${CODE}`,
        "GARNETOPS_HOST_NAME=alpine-01.example.lan",
        "",
      ]);
    });

    it("refuses a download that does not match its checksum", async () => {
      const result = await runAlpine(
        installScript("https://garnetops.example.test", { amd64: "b".repeat(64) }),
      );
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("does not match its checksum");
    });

    it("asks for curl when an internal CA is needed, because BusyBox wget cannot take one", async () => {
      const result = await runAlpine(installScript("https://garnetops.example.test", { amd64: sum }), {
        GARNETOPS_CA_FILE: "/etc/ssl/certs/internal-ca.pem",
      });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("GARNETOPS_CA_FILE needs curl or GNU wget");
    });

    it("never downloads over plain HTTP", async () => {
      const result = await runAlpine(installScript("http://garnetops.example.test", { amd64: sum }));
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("must start with https://");
    });
  });
});
