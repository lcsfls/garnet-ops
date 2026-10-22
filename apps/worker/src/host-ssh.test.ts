import { describe, expect, it } from "vitest";
import { classifySshFailure, hostSshArgs, runCapped } from "./host-ssh.ts";

const base = {
  target: "192.0.2.10",
  port: 2222,
  user: "garnetops",
  keyFile: "/work/ssh/id_ed25519",
  knownHostsFile: "/work/ssh/known_hosts",
  kex: ["curve25519-sha256"],
};

describe("hostSshArgs", () => {
  const args = hostSshArgs(base);
  const options = args.flatMap((a, i) => (args[i - 1] === "-o" ? [a] : []));

  it("pins the host key strictly, under a fixed alias, and never prompts", () => {
    for (const option of [
      "StrictHostKeyChecking=yes",
      "BatchMode=yes",
      "IdentitiesOnly=yes",
      "HostKeyAlias=garnetops-host",
      "UserKnownHostsFile=/work/ssh/known_hosts",
      "GlobalKnownHostsFile=none",
      "UpdateHostKeys=no",
      "PasswordAuthentication=no",
      "PreferredAuthentications=publickey",
    ]) {
      expect(options, option).toContain(option);
    }
  });

  it("allows no forwarding, agent, proxy or terminal, and ignores ssh configuration files", () => {
    expect(args.slice(0, 3)).toEqual(["-F", "none", "-T"]);
    for (const option of [
      "ForwardAgent=no",
      "ForwardX11=no",
      "ClearAllForwardings=yes",
      "ProxyJump=none",
      "ProxyCommand=none",
      "ControlMaster=no",
      "ControlPath=none",
      "PermitLocalCommand=no",
      "RequestTTY=no",
      "IdentityAgent=none",
    ]) {
      expect(options, option).toContain(option);
    }
  });

  it("limits the connection time and offers only the given key exchanges", () => {
    expect(options).toContain("ConnectTimeout=20");
    expect(options).toContain("KexAlgorithms=curve25519-sha256");
  });

  it("ends with the destination and the one remote word, after --", () => {
    expect(args.slice(-3)).toEqual(["--", "192.0.2.10", "inventory"]);
    expect(args).toContain("-l");
    expect(args[args.indexOf("-p") + 1]).toBe("2222");
  });

  it("passes an address that looks like an option as a destination, not as an option", () => {
    // checkHostAddress refuses these long before; this is the second line of defence.
    const risky = hostSshArgs({ ...base, target: "-oProxyCommand=id" });
    expect(risky.slice(-3)).toEqual(["--", "-oProxyCommand=id", "inventory"]);
  });
});

describe("classifySshFailure", () => {
  const cases: [string, number | null, string][] = [
    [
      "@@@@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.",
      255,
      "hostKeyChanged",
    ],
    ["Host key verification failed.", 255, "hostKeyChanged"],
    ["garnetops@192.0.2.10: Permission denied (publickey).", 255, "accessRefused"],
    ["ssh: connect to host 192.0.2.10 port 22: Connection timed out", 255, "hostUnreachable"],
    ["ssh: connect to host 192.0.2.10 port 22: Connection refused", 255, "hostUnreachable"],
    ["kex_exchange_identification: Connection closed by remote host", 255, "hostUnreachable"],
    [
      "Unable to negotiate with 192.0.2.10 port 22: no matching key exchange method found.",
      255,
      "noKeyExchange",
    ],
    ["sh: 1: inventory: not found", 127, "commandRefused"],
    ["", 2, "commandRefused"],
    ["something nobody expected", 255, "hostUnreachable"],
  ];
  for (const [stderr, code, expected] of cases) {
    it(`${expected}: ${stderr.split("\n")[0]?.slice(0, 50) || "(no output)"}`, () => {
      expect(classifySshFailure({ stderr, code })).toBe(expected);
    });
  }
});

describe("runCapped", () => {
  const env = { PATH: process.env.PATH };
  it.skipIf(process.platform === "win32")("returns output and the exit code", async () => {
    const r = await runCapped("sh", ["-c", "printf hello; echo oops >&2; exit 3"], {
      env,
      timeoutMs: 5000,
      maxBytes: 1000,
    });
    expect(r).toMatchObject({ code: 3, timedOut: false, tooLarge: false, stderr: "oops\n" });
    expect(r.stdout.toString()).toBe("hello");
  });

  it.skipIf(process.platform === "win32")("stops a program that prints too much", async () => {
    const r = await runCapped("sh", ["-c", "yes aaaaaaaaaaaaaaaaaaaa"], {
      env,
      timeoutMs: 10_000,
      maxBytes: 10_000,
    });
    expect(r.tooLarge).toBe(true);
    expect(r.stdout.length).toBeLessThanOrEqual(10_000);
  });

  it.skipIf(process.platform === "win32")("stops a program that runs too long", async () => {
    const started = Date.now();
    const r = await runCapped("sh", ["-c", "sleep 30"], { env, timeoutMs: 300, maxBytes: 1000 });
    expect(r.timedOut).toBe(true);
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it("rejects when the program does not exist, without a shell to interpret the name", async () => {
    await expect(
      runCapped("/nonexistent/garnetops-test", [], { env, timeoutMs: 1000, maxBytes: 10 }),
    ).rejects.toThrow(/Could not start/);
  });
});
