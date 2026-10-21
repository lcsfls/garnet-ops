import { describe, expect, it } from "vitest";
import { cloneCommand, cloneErrorMessage, PREFERRED_KEX, sshCommand, sshKexAlgorithms } from "./git.ts";

const base = { url: "https://git.example.test/team/app.git", dir: "/w/src", home: "/w/home", branch: null };
const configOf = (args: string[]) => args.flatMap((a, i) => (args[i - 1] === "-c" ? [a] : []));

describe("cloneCommand", () => {
  it("allows only https and ssh and disables hooks, symlinks, submodules and redirects", () => {
    const { args } = cloneCommand({ ...base, token: null });
    const config = configOf(args);
    expect(config).toEqual(
      expect.arrayContaining([
        "protocol.allow=never",
        "protocol.https.allow=always",
        "protocol.ssh.allow=always",
        "core.symlinks=false",
        "credential.helper=",
        "http.followRedirects=false",
      ]),
    );
    expect(config.some((c) => c.startsWith("core.hooksPath="))).toBe(true);
    expect(args).toEqual(expect.arrayContaining(["--depth=1", "--no-recurse-submodules", "--no-tags"]));
  });

  it("puts the URL after --, so it can never be read as an option", () => {
    const { args } = cloneCommand({ ...base, url: "https://x.test/--upload-pack=evil", token: null });
    expect(args.slice(-3)).toEqual(["--", "https://x.test/--upload-pack=evil", "/w/src"]);
  });

  it("keeps the token out of the arguments and scopes the helper to the repository's origin", () => {
    const token = "ghp_secret_value_123";
    const { args, env } = cloneCommand({ ...base, url: "https://git.example.test:8443/a/b.git", token });
    expect(args.join(" ")).not.toContain(token);
    expect(env.GARNETOPS_GIT_TOKEN).toBe(token);
    const helpers = configOf(args).filter((c) => c.includes(".helper=") && c !== "credential.helper=");
    expect(helpers).toHaveLength(1);
    expect(helpers[0]).toMatch(/^credential\.https:\/\/git\.example\.test:8443\.helper=/);
  });

  it("ignores the user's and system git configuration and never prompts", () => {
    const { env } = cloneCommand({ ...base, token: null });
    expect(env).toMatchObject({ GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0", HOME: "/w/home" });
    expect(env.GIT_CONFIG_GLOBAL).toMatch(/^(NUL|\/dev\/null)$/);
    expect(env.GARNETOPS_GIT_TOKEN).toBeUndefined();
  });

  it("passes a branch as its own argument", () => {
    const { args } = cloneCommand({ ...base, branch: "release/1.2", token: null });
    expect(args).toEqual(expect.arrayContaining(["--branch", "release/1.2"]));
  });
});

describe("ssh", () => {
  const ssh = {
    bin: "C:\\Program Files\\Git\\usr\\bin\\ssh.exe",
    privateKeyFile: "C:\\work\\scan-1\\ssh\\id_ed25519",
    knownHostsFile: "/w/ssh/known_hosts",
    pinned: true,
    kex: ["mlkem768x25519-sha256", "curve25519-sha256"],
  };

  it("runs ssh without user configuration, agent or forwarding, with our key only", () => {
    const command = sshCommand(ssh);
    expect(
      command.startsWith("'C:/Program Files/Git/usr/bin/ssh.exe' -F none -i 'C:/work/scan-1/ssh/id_ed25519'"),
    ).toBe(true);
    for (const option of [
      "BatchMode=yes",
      "IdentitiesOnly=yes",
      "IdentityAgent=none",
      "PasswordAuthentication=no",
      "ForwardAgent=no",
      "ClearAllForwardings=yes",
      "PermitLocalCommand=no",
      "ProxyJump=none",
      "UpdateHostKeys=no",
      "UserKnownHostsFile=/w/ssh/known_hosts",
      "GlobalKnownHostsFile=none",
      "KexAlgorithms=mlkem768x25519-sha256,curve25519-sha256",
    ]) {
      expect(command).toContain(`-o '${option}'`);
    }
  });

  it("requires the pinned host key, and only accepts a new one on first contact", () => {
    expect(sshCommand(ssh)).toContain("-o 'StrictHostKeyChecking=yes'");
    expect(sshCommand({ ...ssh, pinned: false })).toContain("-o 'StrictHostKeyChecking=accept-new'");
  });

  it("quotes paths for the shell git runs the command with", () => {
    const command = sshCommand({ ...ssh, privateKeyFile: "/w/it's here/id" });
    expect(command).toContain("-i '/w/it'\\''s here/id'");
  });

  it("passes the command through the environment, not the arguments", () => {
    const { args, env } = cloneCommand({
      ...base,
      url: "git@git.example.test:team/app.git",
      token: null,
      ssh,
    });
    expect(env.GIT_SSH_COMMAND).toBe(sshCommand(ssh));
    expect(env.SSH_AUTH_SOCK).toBe("");
    expect(args.join(" ")).not.toContain("id_ed25519");
  });

  it("offers post-quantum hybrids first and never SHA-1 or unknown names", () => {
    const supported = ["diffie-hellman-group1-sha1", "curve25519-sha256", "mlkem768x25519-sha256", "made-up"];
    expect(sshKexAlgorithms(supported)).toEqual(["mlkem768x25519-sha256", "curve25519-sha256"]);
    expect(PREFERRED_KEX.some((k) => k.includes("sha1"))).toBe(false);
    expect(PREFERRED_KEX[0]).toBe("mlkem768x25519-sha256");
  });
});

describe("cloneErrorMessage", () => {
  it("never echoes git's output, only a fixed message", () => {
    const stderr = "fatal: Authentication failed for 'https://user:ghp_secret@git.example.test/a.git/'";
    const message = cloneErrorMessage(stderr);
    expect(message).toBe("The repository refused access. Check the token and its read permission.");
    expect(message).not.toContain("ghp_secret");
  });

  it("recognises missing branches, missing repositories and unreachable hosts", () => {
    expect(
      cloneErrorMessage(
        "warning: Could not find remote branch x to clone.\nfatal: Remote branch x not found",
      ),
    ).toBe("The branch does not exist.");
    expect(cloneErrorMessage("remote: Repository not found.")).toContain("not found");
    expect(cloneErrorMessage("fatal: unable to access: Could not resolve host: x")).toBe(
      "The repository host could not be reached.",
    );
    expect(cloneErrorMessage("something else")).toBe("Cloning the repository failed.");
    expect(cloneErrorMessage("git@x: Permission denied (publickey).")).toContain("refused the deploy key");
    expect(cloneErrorMessage("@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @")).toContain("pinned key");
    expect(cloneErrorMessage("Host key verification failed.")).toContain("pinned key");
  });
});
