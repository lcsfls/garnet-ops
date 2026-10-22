/**
 * The agent enrollment helper (ADR 0015): the commands for each operating system and Wazuh
 * series, strict validation, quoting, and that an enrollment password is never an input.
 */
import { describe, expect, it } from "vitest";
import {
  buildEnrollment,
  checkAgentGroups,
  checkAgentName,
  ENROLL_ARCH,
  ENROLL_OS,
  ENROLLMENT_TEMPLATES_VERSION,
  type EnrollInput,
  PASSWORD_PLACEHOLDER,
  posixQuote,
  powershellQuote,
} from "./wazuh-enroll.ts";

/** PowerShell's name for the temporary directory, as the Wazuh documentation writes it. */
const TMP = ["$", "{env:tmp}"].join("");
const v4 = { version: "4.12.0", major: 4, minor: 12 };
const v5 = { version: "5.0.0", major: 5, minor: 0 };
const base = (over: Partial<EnrollInput> = {}): EnrollInput => ({
  os: "debian",
  arch: "amd64",
  manager: "wazuh.example.lan",
  version: v4,
  ...over,
});

function steps(over: Partial<EnrollInput> = {}) {
  const r = buildEnrollment(base(over));
  if (!r.ok) throw new Error(`unexpected problem ${r.problem}`);
  return r;
}
const text = (over: Partial<EnrollInput> = {}) =>
  steps(over)
    .steps.map((s) => s.text)
    .join("\n");

describe("official commands", () => {
  it("Debian and Ubuntu: key, repository, pinned install with the manager address, service", () => {
    const r = steps();
    expect(r.templatesVersion).toBe(ENROLLMENT_TEMPLATES_VERSION);
    expect(r.series).toBe("4.x");
    expect(r.packageVersion).toBe("4.12.0");
    expect(r.preview).toBe(false);
    expect(r.steps.map((s) => s.id)).toEqual(["trust", "repository", "install", "start"]);
    const all = text();
    expect(all).toContain(
      "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg",
    );
    expect(all).toContain(
      'echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list',
    );
    expect(all).toContain("apt-get update");
    expect(all).toContain("WAZUH_MANAGER='wazuh.example.lan' apt-get install wazuh-agent=4.12.0-1");
    expect(all).toContain("systemctl enable wazuh-agent");
    expect(all).toContain("systemctl start wazuh-agent");
  });

  it("RHEL, Rocky and Alma: key import, repository file, yum install", () => {
    const all = text({ os: "rhel" });
    expect(all).toContain("rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH");
    expect(all).toContain("cat > /etc/yum.repos.d/wazuh.repo << 'EOF'");
    expect(all).toContain("baseurl=https://packages.wazuh.com/4.x/yum/");
    expect(all).toContain("gpgcheck=1");
    expect(all).toContain("name=EL-$releasever - Wazuh");
    expect(all).toContain("WAZUH_MANAGER='wazuh.example.lan' yum install wazuh-agent-4.12.0-1");
  });

  it("SUSE: zypper and its repository directory", () => {
    const all = text({ os: "suse" });
    expect(all).toContain("cat > /etc/zypp/repos.d/wazuh.repo << 'EOF'");
    expect(all).toContain("WAZUH_MANAGER='wazuh.example.lan' zypper install wazuh-agent-4.12.0-1");
  });

  it("Windows: PowerShell download of the MSI and msiexec with the properties", () => {
    const r = steps({ os: "windows", group: "default,windows", name: "win-fs01" });
    expect(r.steps.every((s) => s.shell === "powershell")).toBe(true);
    const all = r.steps.map((s) => s.text).join("\n");
    expect(all).toContain(
      `Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi -OutFile ${TMP}\\wazuh-agent.msi`,
    );
    expect(all).toContain(
      `msiexec.exe /i ${TMP}\\wazuh-agent.msi /q WAZUH_MANAGER='wazuh.example.lan' WAZUH_AGENT_GROUP='default,windows' WAZUH_AGENT_NAME='win-fs01'`,
    );
    expect(all).toContain("NET START WazuhSvc");
  });

  it("macOS: the package for the architecture, the variables file and the installer", () => {
    const intel = text({ os: "macos", arch: "amd64" });
    expect(intel).toContain("https://packages.wazuh.com/4.x/macos/wazuh-agent-4.12.0-1.intel64.pkg");
    expect(intel).toContain(`echo "WAZUH_MANAGER='wazuh.example.lan'" > /tmp/wazuh_envs`);
    expect(intel).toContain("sudo installer -pkg ./wazuh-agent.pkg -target /");
    expect(intel).toContain("sudo /Library/Ossec/bin/wazuh-control start");
    const arm = text({ os: "macos", arch: "arm64", group: "default" });
    expect(arm).toContain("wazuh-agent-4.12.0-1.arm64.pkg");
    expect(arm).toContain(`"WAZUH_MANAGER='wazuh.example.lan' && WAZUH_AGENT_GROUP='default'"`);
  });

  it("5.x uses the 5.x repositories and is marked as preview", () => {
    const r = steps({ version: v5 });
    expect(r.series).toBe("5.x");
    expect(r.preview).toBe(true);
    expect(r.steps.map((s) => s.text).join("\n")).toContain("https://packages.wazuh.com/5.x/apt/");
    expect(r.packageVersion).toBe("5.0.0");
  });

  it("pins nothing when the patch level of the manager is not known", () => {
    const all = text({ version: { version: "4.12", major: 4, minor: 12 } });
    expect(all).toContain("apt-get install wazuh-agent\n");
    expect(steps({ version: { version: "4.12", major: 4, minor: 12 } }).packageVersion).toBeNull();
  });

  it("covers every operating system and architecture", () => {
    for (const os of ENROLL_OS) {
      for (const arch of ENROLL_ARCH) {
        const r = buildEnrollment(base({ os, arch }));
        expect(r.ok, `${os} ${arch}`).toBe(true);
      }
    }
  });
});

describe("optional values and the enrollment password", () => {
  it("adds the group and name only when given", () => {
    expect(text()).not.toContain("WAZUH_AGENT_GROUP");
    expect(text()).not.toContain("WAZUH_AGENT_NAME");
    const all = text({ group: "default,web", name: "web-01" });
    expect(all).toContain(
      "WAZUH_MANAGER='wazuh.example.lan' WAZUH_AGENT_GROUP='default,web' WAZUH_AGENT_NAME='web-01' apt-get",
    );
  });

  it("puts a marked placeholder where the password goes, and offers no way to type one", () => {
    const r = steps({ password: true });
    expect(r.passwordPlaceholder).toBe(true);
    expect(text({ password: true })).toContain(`WAZUH_REGISTRATION_PASSWORD='${PASSWORD_PLACEHOLDER}'`);
    expect(PASSWORD_PLACEHOLDER).toMatch(/^<[A-Z_]+>$/);
    expect(text()).not.toContain("PASSWORD");
    // The input type has no password field: any extra property is ignored.
    const sneaky = {
      ...base({ password: true }),
      registrationPassword: "hunter2hunter2",
      enrollmentPassword: "x",
    };
    const out = buildEnrollment(sneaky as EnrollInput);
    expect(JSON.stringify(out)).not.toContain("hunter2");
  });
});

describe("validation and quoting", () => {
  it.each([
    ["manager", { manager: "host; rm -rf /" }],
    ["manager", { manager: "$(id)" }],
    ["manager", { manager: "host`id`" }],
    ["manager", { manager: "host name" }],
    ["manager", { manager: "" }],
    ["manager", { manager: "host'$(id)'" }],
    ["group", { group: "default; id" }],
    ["group", { group: "a,b,c,d,e,f" }],
    ["group", { group: "default," }],
    ["group", { group: "$(id)" }],
    ["group", { group: "a b" }],
    ["name", { name: "web 01" }],
    ["name", { name: "web'01" }],
    ["name", { name: "`id`" }],
    ["name", { name: "x".repeat(129) }],
    ["os", { os: "plan9" }],
    ["arch", { arch: "sparc" }],
    ["version", { version: { version: "3.13.6", major: 3, minor: 13 } }],
    ["version", { version: { version: "6.0.0", major: 6, minor: 0 } }],
  ] as const)("refuses %s: %j", (problem, over) => {
    expect(buildEnrollment(base(over as Partial<EnrollInput>))).toEqual({ ok: false, problem });
  });

  it("no input can add a line or a command: every output line comes from the template", () => {
    for (const os of ENROLL_OS) {
      const out = text({ os, group: "default,web", name: "web-01", password: true });
      for (const bad of [";", "&&&", "$(", "`", "\r"]) expect(out, `${os} ${bad}`).not.toContain(bad);
    }
  });

  it("quotes for POSIX shells and PowerShell even though values are validated", () => {
    expect(posixQuote("plain")).toBe("'plain'");
    expect(posixQuote("it's")).toBe("'it'\\''s'");
    expect(posixQuote("$(id)")).toBe("'$(id)'");
    expect(powershellQuote("plain")).toBe("'plain'");
    expect(powershellQuote("it's")).toBe("'it''s'");
  });

  it("checks groups and names as plain words", () => {
    expect(checkAgentGroups("default, web")).toBe("default,web");
    expect(checkAgentGroups("")).toBeNull();
    expect(checkAgentName("web-01.example")).toBe("web-01.example");
    expect(checkAgentName("a/b")).toBeNull();
  });

  it("lower-cases the manager address and keeps IPv6", () => {
    expect(text({ manager: "Wazuh.Example.LAN" })).toContain("WAZUH_MANAGER='wazuh.example.lan'");
    expect(text({ manager: "2001:db8::1" })).toContain("WAZUH_MANAGER='2001:db8::1'");
  });
});
